from __future__ import annotations

import base64
import hashlib
import os
import queue
import re
import secrets
import socket
import sys
import tarfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
from rich.console import Console
from rich.panel import Panel
from tqdm import tqdm

from lan_transfer.crypto import (
    generate_credentials,
    get_client_auth_token,
    get_encryptor,
    get_key_verification_hash,
    verify_pin,
)
from lan_transfer.discover import LanTransferBroadcaster
from lan_transfer.utils import format_size, get_local_ip

console = Console()

CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks for high-throughput LAN streaming
_RANGE_RE = re.compile(r"^bytes=(\d+)-$")


class _StreamAborted(Exception):
    """Raised internally to unwind TarStreamer when the receiver disconnects early."""


class TarStreamer:
    """Streams a directory as a .tar or .tar.gz archive in background 1 MiB chunks without temp files."""

    def __init__(self, directory: str, compress: bool = False, quiet: bool = False):
        self.directory = os.path.normpath(os.path.abspath(directory))
        self.compress = compress
        self.quiet = quiet
        self.q: queue.Queue[bytes | None] = queue.Queue(maxsize=32)
        self._closed = threading.Event()
        self.exhausted = False
        self.error: Exception | None = None
        self.buffer = b""
        self._write_buffer = bytearray()
        self.total_size = self._calculate_total_size()
        self.thread = threading.Thread(target=self._build_tar, name="TarStreamerWorker", daemon=True)
        self.thread.start()

    def _calculate_total_size(self) -> int:
        total = 0
        entries = 0
        for root, dirs, files in os.walk(self.directory, followlinks=False):
            entries += len(dirs) + len(files) + 1
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if not os.path.islink(fpath):
                        total += os.path.getsize(fpath)
                except OSError:
                    continue
        # TAR adds 512-byte header blocks + 512-byte alignment + 1024-byte EOF marker
        return total + (entries * 1024) + 1024

    def _enqueue(self, chunk: bytes) -> None:
        while not self._closed.is_set():
            try:
                self.q.put(chunk, timeout=0.2)
                return
            except queue.Full:
                continue
        raise _StreamAborted()

    def write(self, b: bytes | bytearray | memoryview) -> int:
        if self._closed.is_set():
            raise _StreamAborted()
        self._write_buffer.extend(b)
        if len(self._write_buffer) >= CHUNK_SIZE:
            self._enqueue(bytes(self._write_buffer))
            self._write_buffer.clear()
        return len(b)

    def flush(self) -> None:
        pass

    def _add_path_safely(self, tar: tarfile.TarFile, full_path: str, arc_path: str) -> None:
        if self._closed.is_set():
            raise _StreamAborted()

        try:
            st = os.lstat(full_path)
        except OSError as exc:
            if not self.quiet:
                console.print(f"[yellow][!] Skipping inaccessible path '{full_path}': {exc}[/yellow]")
            return

        # Skip symlinks and special device/socket files for safety and portability
        if os.path.islink(full_path):
            return

        if os.path.isdir(full_path):
            tarinfo = tar.gettarinfo(full_path, arcname=arc_path)
            tarinfo.size = 0
            tar.addfile(tarinfo)
            try:
                entries = sorted(os.scandir(full_path), key=lambda e: e.name)
            except OSError as exc:
                if not self.quiet:
                    console.print(f"[yellow][!] Skipping unreadable directory '{full_path}': {exc}[/yellow]")
                return
            for entry in entries:
                child_arc = f"{arc_path}/{entry.name}"
                self._add_path_safely(tar, entry.path, child_arc)
        elif os.path.isfile(full_path):
            try:
                with open(full_path, "rb") as fobj:
                    tarinfo = tar.gettarinfo(arcname=arc_path, fileobj=fobj)
                    tar.addfile(tarinfo, fileobj=fobj)
            except _StreamAborted:
                raise
            except OSError as exc:
                if not self.quiet:
                    console.print(f"[yellow][!] Skipping locked/unreadable file '{full_path}': {exc}[/yellow]")

    def _build_tar(self) -> None:
        try:
            mode = "w|gz" if self.compress else "w|"
            tar_kwargs: dict = {"fileobj": self, "mode": mode}
            if self.compress:
                tar_kwargs["compresslevel"] = 1  # Fast compression suitable for LAN links

            arcname = os.path.basename(self.directory) or "archive"
            with tarfile.open(**tar_kwargs) as tar:
                self._add_path_safely(tar, self.directory, arcname)

            if self._write_buffer and not self._closed.is_set():
                self._enqueue(bytes(self._write_buffer))
                self._write_buffer.clear()
        except _StreamAborted:
            pass
        except Exception as exc:
            self.error = exc
            if not self.quiet:
                console.print(f"[red][X] Error creating TAR stream: {exc}[/red]")
        finally:
            while not self._closed.is_set():
                try:
                    self.q.put(None, timeout=0.2)
                    break
                except queue.Full:
                    continue

    def read(self, size: int = -1) -> bytes:
        if self.error is not None:
            raise self.error
        if self.exhausted or self._closed.is_set():
            return b""

        data = bytearray()
        while size == -1 or len(data) < size:
            if not self.buffer:
                try:
                    chunk = self.q.get(timeout=0.5)
                except queue.Empty:
                    if self.error is not None:
                        raise self.error
                    if self._closed.is_set():
                        break
                    continue

                if chunk is None:
                    self.exhausted = True
                    if self.error is not None:
                        raise self.error
                    break
                self.buffer = chunk

            needed = (size - len(data)) if size != -1 else len(self.buffer)
            data.extend(self.buffer[:needed])
            self.buffer = self.buffer[needed:]

        return bytes(data)

    def close(self) -> None:
        """Signals background TAR builder to stop immediately and drains queue."""
        self._closed.set()
        try:
            while True:
                self.q.get_nowait()
        except queue.Empty:
            pass


class TransferRequestHandler(BaseHTTPRequestHandler):
    """Authenticated, encrypted HTTP/1.1 handler supporting chunked folders and resumable files."""

    protocol_version = "HTTP/1.1"
    server: "LanTransferServer"

    def log_message(self, format: str, *args) -> None:
        pass

    def _send_plain_error(self, code: int, message: str, reason: str = "") -> None:
        body = f"{code} {message}\n".encode("utf-8")
        self.send_response(code, message)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if reason:
            self.send_header("X-LAN-REASON", reason)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

    def do_GET(self) -> None:
        self.close_connection = True
        srv = self.server
        client_ip = self.client_address[0]

        # Ignore browser favicon probes without consuming slots or PIN attempts
        if self.path.split("?", 1)[0] == "/favicon.ico":
            self._send_plain_error(404, "Not Found")
            return

        # 1. Check brute-force rate limits
        with srv.lock:
            if srv.security_shutdown or srv.failed_attempts_by_ip.get(client_ip, 0) >= srv.max_pin_attempts_per_ip:
                self._send_plain_error(429, "Too Many Failed PIN Attempts", reason="LOCKED")
                return

        # 2. Constant-time PIN authentication
        client_pin = self.headers.get("X-LAN-PIN")
        if not verify_pin(client_pin, srv.pin):
            with srv.lock:
                ip_fails = srv.failed_attempts_by_ip.get(client_ip, 0) + 1
                srv.failed_attempts_by_ip[client_ip] = ip_fails
                srv.total_failed_attempts += 1
                if ip_fails == srv.max_pin_attempts_per_ip and not srv.quiet:
                    console.print(
                        f"\n[red][SEC] Blocked IP {client_ip} after {ip_fails} failed PIN attempts.[/red]"
                    )
                if srv.total_failed_attempts >= srv.max_total_pin_attempts:
                    srv.security_shutdown = True
                    if not srv.quiet:
                        console.print(
                            "\n[bold red][SEC] Global failed PIN limit reached. Shutting down server.[/bold red]"
                        )
            self._send_plain_error(403, "Access Denied: Incorrect PIN", reason="PIN")
            return

        # 2b. Pre-stream AES key possession check (prevents burning slots on small files with wrong key)
        client_auth = self.headers.get("X-LAN-AUTH", "")
        if not client_auth or not secrets.compare_digest(client_auth, srv.expected_client_auth_b64):
            self._send_plain_error(403, "Access Denied: Incorrect Encryption Key", reason="KEY")
            return

        # 3. Reserve download slot atomically (briefly wait if a disconnected socket is still unwinding)
        with srv.slot_cond:
            deadline = time.monotonic() + 2.0
            while srv.completed_downloads + srv.active_downloads >= srv.max_users:
                if srv.completed_downloads >= srv.max_users or srv.security_shutdown:
                    break
                wait_left = deadline - time.monotonic()
                if wait_left <= 0:
                    break
                srv.slot_cond.wait(timeout=wait_left)

            if srv.completed_downloads + srv.active_downloads >= srv.max_users:
                self._send_plain_error(503, "All Download Slots Busy or Completed")
                return
            srv.active_downloads += 1
            srv.last_activity = time.monotonic()
            remaining_display = srv.max_users - srv.completed_downloads

        transfer_succeeded = False
        stream_id = ""
        source = None
        try:
            if srv.is_dir:
                if not os.path.isdir(srv.filepath):
                    self._send_plain_error(404, "Directory Not Found")
                    return
                stream_id = secrets.token_hex(8)
                nonce = secrets.token_bytes(16)
                start_offset = 0
                source = TarStreamer(srv.filepath, compress=srv.compress, quiet=srv.quiet)
                total_size = source.total_size

                self.send_response(200)
                self.send_header("Content-Type", "application/gzip" if srv.compress else "application/x-tar")
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.send_header("X-LAN-NONCE", base64.b64encode(nonce).decode("utf-8"))
                self.send_header("X-LAN-VERIFY", srv.verify_hash_b64)
                self.send_header("X-LAN-ISDIR", "true")
                self.send_header("X-LAN-COMPRESSED", "true" if srv.compress else "false")
                self.send_header("X-LAN-FILENAME", urllib.parse.quote(srv.filename))
                self.send_header("X-LAN-TRANSFER-ID", stream_id)
                self.send_header("X-LAN-ESTIMATED-SIZE", str(total_size))
                self.end_headers()
            else:
                if not os.path.isfile(srv.filepath):
                    self._send_plain_error(404, "File Not Found")
                    return
                st = os.stat(srv.filepath)
                file_size = st.st_size
                total_size = file_size

                # Check if client requested a valid resumable Range
                start_offset = 0
                status_code = 200
                req_transfer_id = self.headers.get("X-LAN-TRANSFER-ID", "")
                range_hdr = self.headers.get("Range", "")
                range_match = _RANGE_RE.match(range_hdr.strip()) if range_hdr else None

                with srv.lock:
                    saved_session = srv.resumable_streams.get(req_transfer_id)

                if (
                    range_match
                    and saved_session is not None
                    and saved_session[1] == st.st_mtime_ns
                    and saved_session[2] == file_size
                ):
                    requested_start = int(range_match.group(1))
                    if 0 < requested_start < file_size:
                        start_offset = requested_start
                        status_code = 206
                        stream_id = req_transfer_id
                        nonce = saved_session[0]
                    else:
                        stream_id = secrets.token_hex(8)
                        nonce = secrets.token_bytes(16)
                else:
                    stream_id = secrets.token_hex(8)
                    nonce = secrets.token_bytes(16)

                if status_code == 200:
                    with srv.lock:
                        srv.resumable_streams[stream_id] = (nonce, st.st_mtime_ns, file_size)

                source = open(srv.filepath, "rb")
                if start_offset > 0:
                    source.seek(start_offset)

                self.send_response(status_code)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(file_size - start_offset))
                if status_code == 206:
                    self.send_header("Content-Range", f"bytes {start_offset}-{file_size - 1}/{file_size}")
                self.send_header("Connection", "close")
                self.send_header("X-LAN-NONCE", base64.b64encode(nonce).decode("utf-8"))
                self.send_header("X-LAN-VERIFY", srv.verify_hash_b64)
                self.send_header("X-LAN-ISDIR", "false")
                self.send_header("X-LAN-COMPRESSED", "false")
                self.send_header("X-LAN-FILENAME", urllib.parse.quote(srv.filename))
                self.send_header("X-LAN-TRANSFER-ID", stream_id)
                self.send_header("X-LAN-OFFSET", str(start_offset))
                self.send_header("X-LAN-TOTAL-SIZE", str(file_size))
                self.end_headers()

            encryptor = get_encryptor(srv.key_bytes, nonce, byte_offset=start_offset)
            sha256_hasher = hashlib.sha256() if start_offset == 0 else None
            bytes_sent = 0

            pbar = None
            if not srv.quiet:
                pbar = tqdm(
                    desc=f"Uploading [{client_ip}] (Slots left: {remaining_display})",
                    initial=start_offset,
                    total=total_size if total_size > 0 else None,
                    unit="iB",
                    unit_scale=True,
                    unit_divisor=1024,
                    bar_format="{l_bar}{bar:40}{r_bar}",
                    colour="green",
                )

            try:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if sha256_hasher is not None:
                        sha256_hasher.update(chunk)

                    encrypted_chunk = encryptor.update(chunk)
                    if srv.is_dir:
                        self.wfile.write(f"{len(encrypted_chunk):X}\r\n".encode("ascii"))
                        self.wfile.write(encrypted_chunk)
                        self.wfile.write(b"\r\n")
                    else:
                        self.wfile.write(encrypted_chunk)

                    bytes_sent += len(chunk)
                    with srv.lock:
                        srv.last_activity = time.monotonic()

                    if pbar is not None:
                        if pbar.total is not None and (pbar.n + len(chunk)) > pbar.total:
                            pbar.total = pbar.n + len(chunk)
                        pbar.update(len(chunk))

                tail = encryptor.finalize()
                if tail:
                    if srv.is_dir:
                        self.wfile.write(f"{len(tail):X}\r\n".encode("ascii"))
                        self.wfile.write(tail)
                        self.wfile.write(b"\r\n")
                    else:
                        self.wfile.write(tail)

                if srv.is_dir:
                    if isinstance(source, TarStreamer) and source.error is not None:
                        raise source.error
                    # Terminating chunk confirms 100% of TAR archive was generated cleanly
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    transfer_succeeded = True
                else:
                    self.wfile.flush()
                    if start_offset + bytes_sent == total_size:
                        transfer_succeeded = True

                if pbar is not None and transfer_succeeded and pbar.total is not None:
                    pbar.total = pbar.n
                    pbar.refresh()
            finally:
                if pbar is not None:
                    pbar.close()

            if transfer_succeeded and not srv.quiet:
                if sha256_hasher is not None:
                    digest = sha256_hasher.hexdigest()
                    srv.last_sha256 = digest
                    console.print(f"[dim][SEC] Sent SHA-256 ({client_ip}): {digest}[/dim]")
                else:
                    console.print(
                        f"[dim][OK] Resumed upload completed for {client_ip} (+{format_size(bytes_sent)}).[/dim]"
                    )

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            if not srv.quiet:
                console.print(
                    f"[yellow][!] Receiver {client_ip} disconnected early (download slot preserved).[/yellow]"
                )
        except OSError as exc:
            if not srv.quiet:
                console.print(f"[yellow][!] Network error with {client_ip}: {exc} (slot preserved).[/yellow]")
        finally:
            if source is not None:
                try:
                    source.close()
                except Exception:
                    pass
            with srv.slot_cond:
                srv.active_downloads = max(0, srv.active_downloads - 1)
                if transfer_succeeded:
                    srv.completed_downloads += 1
                    srv.downloads_remaining = max(0, srv.max_users - srv.completed_downloads)
                    if not srv.is_dir:
                        srv.resumable_streams.pop(stream_id, None)
                srv.last_activity = time.monotonic()
                srv.slot_cond.notify_all()


class LanTransferServer(ThreadingTCPServer):
    """Multi-threaded TCP server managing state, slots, resumable nonces, and security."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        filepath: str,
        users: int = 1,
        compress: bool = False,
        quiet: bool = False,
        max_pin_attempts_per_ip: int = 5,
        max_total_pin_attempts: int = 15,
    ):
        self.filepath = os.path.normpath(os.path.abspath(filepath))
        self.is_dir = os.path.isdir(self.filepath)
        self.compress = compress and self.is_dir
        self.quiet = quiet

        base_name = os.path.basename(self.filepath)
        if not base_name:
            drive = os.path.splitdrive(self.filepath)[0].rstrip(":\\/")
            base_name = f"drive_{drive}" if drive else "archive"

        if self.is_dir:
            self.filename = f"{base_name}.tar.gz" if self.compress else f"{base_name}.tar"
        else:
            self.filename = base_name

        self.pin, self.key_bytes, self.key_b64 = generate_credentials()
        self.verify_hash_b64 = get_key_verification_hash(self.key_bytes)
        self.expected_client_auth_b64 = get_client_auth_token(self.key_bytes)

        self.lock = threading.Lock()
        self.slot_cond = threading.Condition(self.lock)
        self.max_users = users
        self.downloads_remaining = users
        self.completed_downloads = 0
        self.active_downloads = 0

        self.max_pin_attempts_per_ip = max_pin_attempts_per_ip
        self.max_total_pin_attempts = max_total_pin_attempts
        self.failed_attempts_by_ip: dict[str, int] = {}
        self.total_failed_attempts = 0
        self.security_shutdown = False

        # Maps stream_id -> (nonce_bytes, st_mtime_ns, file_size)
        self.resumable_streams: dict[str, tuple[bytes, int, int]] = {}
        self.last_sha256: str | None = None
        self.last_activity = time.monotonic()

        super().__init__(server_address, TransferRequestHandler)
        self.timeout = 0.5

    def handle_error(self, request, client_address) -> None:
        # Suppress noisy tracebacks when clients disconnect abruptly during handshake
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout)):
            return
        if not self.quiet:
            console.print(f"[red][X] Unexpected handler error from {client_address[0]}: {exc}[/red]")


def _estimate_directory_raw_bytes(directory: str) -> int:
    total = 0
    for root, _, files in os.walk(directory, followlinks=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if not os.path.islink(fpath):
                    total += os.path.getsize(fpath)
            except OSError:
                continue
    return total


def send_file(
    filepath: str,
    users: int = 1,
    port: int = 0,
    host: str | None = None,
    compress: bool = False,
    expire_minutes: float = 0.0,
) -> None:
    if not os.path.exists(filepath):
        console.print(f"[red][X] Error: The path '{filepath}' does not exist.[/red]")
        sys.exit(1)

    if users < 1:
        console.print("[red][X] Error: --users must be at least 1.[/red]")
        sys.exit(1)

    if not (0 <= port <= 65535):
        console.print("[red][X] Error: --port must be between 0 and 65535.[/red]")
        sys.exit(1)

    bind_addr = host if host else "0.0.0.0"
    try:
        server = LanTransferServer(
            (bind_addr, port),
            filepath=filepath,
            users=users,
            compress=compress,
        )
    except OSError as exc:
        console.print(f"[red][X] Error binding server on {bind_addr}:{port}: {exc}[/red]")
        sys.exit(1)

    advertise_ip = host if (host and host != "0.0.0.0") else get_local_ip()
    actual_port = server.server_address[1]
    encoded_filename = urllib.parse.quote(server.filename)

    if server.is_dir:
        raw_bytes = _estimate_directory_raw_bytes(server.filepath)
        mode_tag = "Compressed .tar.gz Stream" if server.compress else "Streaming .tar Directory"
        size_display = f"~{format_size(raw_bytes)} ({mode_tag})"
        broadcast_size = raw_bytes
    else:
        raw_bytes = os.path.getsize(server.filepath)
        size_display = format_size(raw_bytes)
        broadcast_size = raw_bytes

    extra_lines = ""
    if expire_minutes > 0:
        extra_lines = f"[bold magenta][i] Auto-Expire:[/bold magenta] {expire_minutes:g} min idle\n"

    console.print(
        Panel.fit(
            f"[bold green][*] Ready to send:[/bold green] {server.filename} ({users} max downloads)\n"
            f"[bold yellow][i] Size:[/bold yellow] {size_display}\n"
            f"{extra_lines}"
            f"[bold red][SEC] Security PIN:[/bold red] {server.pin}\n\n"
            f"Receiver command:\n\n"
            f"[bold cyan]lan-transfer receive {advertise_ip}:{actual_port} {encoded_filename} "
            f"--pin {server.pin} --key {server.key_b64}[/bold cyan]",
            title="[bold blue]LAN Transfer Shield - Sender Mode[/bold blue]",
        )
    )

    broadcaster = LanTransferBroadcaster(
        ip=advertise_ip,
        port=actual_port,
        filename=server.filename,
        size_bytes=broadcast_size,
        is_dir=server.is_dir,
        compressed=server.compress,
    )
    broadcaster.start()

    expire_seconds = expire_minutes * 60.0 if expire_minutes > 0 else 0.0

    try:
        console.print("\n[dim]Waiting for receivers to connect... (Press Ctrl+C to cancel)[/dim]")
        while True:
            server.handle_request()
            with server.lock:
                done = server.downloads_remaining <= 0 and server.active_downloads == 0
                sec_stop = server.security_shutdown and server.active_downloads == 0
                idle_elapsed = time.monotonic() - server.last_activity
                idle_expired = (
                    expire_seconds > 0
                    and server.active_downloads == 0
                    and idle_elapsed >= expire_seconds
                )

            if done:
                console.print("\n[bold green][OK] All transfers complete. Server safely closed.[/bold green]")
                break
            if sec_stop:
                break
            if idle_expired:
                console.print("\n[yellow][!] Idle timeout reached. Server safely closed.[/yellow]")
                break
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Transfer cancelled by user.[/yellow]")
    finally:
        broadcaster.stop()
        server.server_close()
