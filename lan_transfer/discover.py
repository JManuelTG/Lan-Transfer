from __future__ import annotations

import socket
import threading
import time
import urllib.parse
from rich.console import Console
from rich.table import Table
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from lan_transfer.utils import format_size

console = Console()


def _truncate_utf8(text: str, max_bytes: int = 200) -> bytes:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded
    return encoded[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8")


class LanTransferBroadcaster:
    """Broadcasts an active LAN Transfer session over mDNS/Zeroconf."""

    def __init__(
        self,
        ip: str,
        port: int,
        filename: str,
        size_bytes: int = -1,
        is_dir: bool = False,
        compressed: bool = False,
    ):
        self.ip = ip
        self.port = port
        self.filename = filename
        self.size_bytes = size_bytes
        self.is_dir = is_dir
        self.compressed = compressed
        self.zeroconf: Zeroconf | None = None
        self.info: ServiceInfo | None = None
        self._active = False

    def start(self) -> bool:
        try:
            safe_ip_tag = self.ip.replace(".", "-").replace(":", "-")
            service_name = f"LAN-Transfer-{safe_ip_tag}-{self.port}._http._tcp.local."
            self.zeroconf = Zeroconf()
            self.info = ServiceInfo(
                "_http._tcp.local.",
                service_name,
                addresses=[socket.inet_aton(self.ip)],
                port=self.port,
                properties={
                    "filename": _truncate_utf8(self.filename, 200),
                    "size": str(self.size_bytes).encode("utf-8"),
                    "isdir": b"true" if self.is_dir else b"false",
                    "compressed": b"true" if self.compressed else b"false",
                },
                server=f"lan-transfer-{safe_ip_tag}-{self.port}.local.",
            )
            self.zeroconf.register_service(self.info)
            self._active = True
            return True
        except Exception as exc:
            console.print(
                f"[yellow][!] Notice: LAN radar broadcast unavailable ({exc}). "
                f"Direct receive command still works.[/yellow]"
            )
            self._cleanup_silent()
            return False

    def _cleanup_silent(self) -> None:
        if self.zeroconf is not None:
            try:
                self.zeroconf.close()
            except Exception:
                pass
            self.zeroconf = None

    def stop(self) -> None:
        if not self._active or self.zeroconf is None:
            self._cleanup_silent()
            return
        try:
            if self.info is not None:
                self.zeroconf.unregister_service(self.info)
        except Exception:
            pass
        finally:
            self._active = False
            self._cleanup_silent()


class TransferListener(ServiceListener):
    """Thread-safe mDNS listener filtering exclusively for LAN-Transfer services."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._services: dict[str, ServiceInfo] = {}

    @property
    def services(self) -> list[ServiceInfo]:
        with self._lock:
            return list(self._services.values())

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        with self._lock:
            self._services.pop(name, None)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if not name.startswith("LAN-Transfer-"):
            return
        info = zc.get_service_info(type_, name, timeout=2000)
        if info:
            with self._lock:
                self._services[name] = info

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if not name.startswith("LAN-Transfer-"):
            return
        info = zc.get_service_info(type_, name, timeout=2000)
        if info:
            with self._lock:
                self._services[name] = info


def _extract_ipv4(svc: ServiceInfo) -> str | None:
    for raw_addr in svc.addresses:
        if len(raw_addr) == 4:
            return socket.inet_ntoa(raw_addr)
    for parsed in svc.parsed_addresses():
        if ":" not in parsed:
            return parsed
    return None


def discover_transfers(scan_timeout: float = 3.0, output: str | None = None) -> None:
    if scan_timeout <= 0:
        scan_timeout = 3.0

    console.print(f"[cyan][*] Scanning local network for LAN Transfers ({scan_timeout:.1f}s)...[/cyan]")
    zeroconf = Zeroconf()
    listener = TransferListener()
    ServiceBrowser(zeroconf, "_http._tcp.local.", listener)

    try:
        time.sleep(scan_timeout)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Discovery cancelled.[/yellow]")
        return
    finally:
        zeroconf.close()

    valid_entries: list[tuple[str, int, str, str, str, bool]] = []
    for svc in listener.services:
        ip = _extract_ipv4(svc)
        if not ip or not svc.port:
            continue
        props = svc.properties or {}
        filename = (props.get(b"filename") or b"unknown").decode("utf-8", errors="replace")
        raw_size = (props.get(b"size") or b"-1").decode("utf-8", errors="replace")
        is_dir = (props.get(b"isdir") or b"false").decode("utf-8", errors="replace") == "true"
        compressed = (props.get(b"compressed") or b"false").decode("utf-8", errors="replace") == "true"

        try:
            size_int = int(raw_size)
        except ValueError:
            size_int = -1

        if is_dir:
            type_label = "Folder (tar.gz)" if compressed else "Folder (tar)"
            size_label = f"~{format_size(size_int)}" if size_int >= 0 else "Streaming"
        else:
            type_label = "File"
            size_label = format_size(size_int) if size_int >= 0 else "Unknown"

        valid_entries.append((ip, svc.port, filename, type_label, size_label, is_dir))

    if not valid_entries:
        console.print("[yellow][!] No active LAN Transfers found on the network.[/yellow]")
        return

    table = Table(title="Available LAN Transfers")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="green")
    table.add_column("Type", style="blue")
    table.add_column("Size", style="yellow", justify="right")
    table.add_column("Sender IP:Port", style="magenta")

    for idx, (ip, port, filename, type_label, size_label, _) in enumerate(valid_entries, start=1):
        table.add_row(str(idx), filename, type_label, size_label, f"{ip}:{port}")

    console.print(table)

    try:
        choice_raw = input("\nEnter the ID of the transfer to download (or press Enter to exit): ").strip()
        if not choice_raw:
            return
        if not choice_raw.isdigit():
            console.print("[red][X] Invalid ID.[/red]")
            return

        choice = int(choice_raw)
        if choice < 1 or choice > len(valid_entries):
            console.print("[red][X] Invalid ID.[/red]")
            return

        ip, port, filename, _, _, is_dir = valid_entries[choice - 1]
        pin = input(f"Enter the 4-digit PIN for '{filename}': ").strip()
        key_b64 = input(f"Enter the Encryption Key for '{filename}': ").strip()

        extract_dir = False
        if is_dir:
            ans = input("Automatically extract folder after download? [Y/n]: ").strip().lower()
            extract_dir = ans in ("", "y", "yes", "s", "si")

        from lan_transfer.receiver import receive_file

        encoded_filename = urllib.parse.quote(filename)
        console.print("")
        receive_file(
            address=f"{ip}:{port}",
            filename=encoded_filename,
            pin=pin,
            key_b64=key_b64,
            output=output,
            extract=extract_dir,
        )
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow][!] Discovery cancelled.[/yellow]")
