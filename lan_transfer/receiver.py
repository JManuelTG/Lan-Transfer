from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import urllib.parse
import requests
from rich.console import Console
from rich.panel import Panel
from tqdm import tqdm

from lan_transfer.crypto import (
    CTR_NONCE_SIZE,
    decode_and_validate_key,
    get_client_auth_token,
    get_decryptor,
    verify_key,
)
from lan_transfer.utils import (
    format_size,
    resolve_output_path,
    safe_extract_tar,
    sanitize_filename,
)

console = Console()

BLOCK_SIZE = 1024 * 1024  # 1 MiB read chunks


def _normalize_address(address: str) -> str:
    cleaned = address.strip()
    for prefix in ("http://", "https://"):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    return cleaned.rstrip("/")


def _is_directory_output(output: str | None, extract: bool = False) -> bool:
    if not output:
        return True
    if extract or output.endswith(("/", "\\")):
        return True
    expanded = os.path.abspath(os.path.expanduser(output))
    if os.path.isdir(expanded):
        return True
    if os.path.isfile(expanded):
        return False
    return os.path.splitext(os.path.basename(expanded))[1] == ""


def _determine_dest_dir_and_name(
    default_filename: str,
    output: str | None,
    extract: bool = False,
) -> tuple[str, str]:
    safe_default = sanitize_filename(default_filename)
    if output:
        expanded = os.path.abspath(os.path.expanduser(output))
        if _is_directory_output(output, extract=extract):
            return expanded, safe_default
        parent = os.path.dirname(expanded) or os.path.abspath(".")
        custom_name = sanitize_filename(os.path.basename(expanded))
        return parent, custom_name
    return os.path.abspath("."), safe_default


def _find_resume_candidate(
    dest_dir: str,
    known_filename: str | None,
) -> tuple[str | None, int, str]:
    """Returns (part_path, part_size, saved_transfer_id) if a resumable .part exists."""
    if not os.path.isdir(dest_dir):
        return None, 0, ""

    candidates: list[str] = []
    if known_filename:
        candidates.append(os.path.join(dest_dir, f"{known_filename}.part.meta"))
    else:
        try:
            meta_files = [
                os.path.join(dest_dir, f)
                for f in os.listdir(dest_dir)
                if f.endswith(".part.meta")
            ]
            if len(meta_files) == 1:
                candidates.append(meta_files[0])
        except OSError:
            pass

    for meta_path in candidates:
        part_path = meta_path[:-5]  # strip ".meta"
        if not (os.path.isfile(meta_path) and os.path.isfile(part_path)):
            continue
        try:
            part_size = os.path.getsize(part_path)
            if part_size <= 0:
                continue
            with open(meta_path, "r", encoding="utf-8") as mf:
                meta = json.load(mf)
            transfer_id = str(meta.get("transfer_id", ""))
            if transfer_id:
                return part_path, part_size, transfer_id
        except Exception:
            continue

    return None, 0, ""


def _hash_existing_file(filepath: str, limit_bytes: int) -> hashlib._Hash:
    hasher = hashlib.sha256()
    remaining = limit_bytes
    with open(filepath, "rb") as f:
        while remaining > 0:
            chunk = f.read(min(BLOCK_SIZE, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
    return hasher


def _cleanup_files(*paths: str | None) -> None:
    for p in paths:
        if p and os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def receive_file(
    address: str,
    filename: str | None = None,
    pin: str = "",
    key_b64: str = "",
    output: str | None = None,
    extract: bool = False,
    overwrite: bool = False,
    resume: bool = True,
    quiet: bool = False,
) -> bool:
    """
    Connects to a LAN Transfer sender, authenticates, decrypts on the fly,
    supports automatic resume via HTTP Range + AES-CTR seeking, and verifies integrity.
    Returns True on success, False otherwise.
    """
    norm_addr = _normalize_address(address)
    if ":" not in norm_addr:
        if not quiet:
            console.print(
                "[red][X] Invalid sender address. Expected format IP:PORT (e.g. 192.168.1.5:54321).[/red]"
            )
        return False

    clean_pin = pin.strip()
    if not clean_pin:
        if not quiet:
            console.print("[red][X] Error: Security PIN cannot be empty.[/red]")
        return False

    try:
        key_bytes = decode_and_validate_key(key_b64)
    except ValueError as exc:
        if not quiet:
            console.print(f"[red][X] Key Error: {exc}[/red]")
        return False

    cli_decoded_name = sanitize_filename(urllib.parse.unquote(filename)) if filename else None
    url_segment = urllib.parse.quote(cli_decoded_name) if cli_decoded_name else "download"
    url = f"http://{norm_addr}/{url_segment}"

    display_label = cli_decoded_name if cli_decoded_name else "(auto-detecting from server)"
    if not quiet:
        console.print(
            Panel.fit(
                f"[bold blue][v] Downloading (Secure):[/bold blue] {display_label}\n"
                f"[bold yellow][i] From:[/bold yellow] {norm_addr}",
                title="[bold cyan]LAN Transfer Shield - Receiver Mode[/bold cyan]",
            )
        )

    # Pre-check if a partial download exists locally for resume
    explicit_file_output = bool(output and not _is_directory_output(output, extract=extract))
    prelim_dir, prelim_name = _determine_dest_dir_and_name(
        cli_decoded_name or "download", output, extract=extract
    )
    known_lookup = prelim_name if (cli_decoded_name or explicit_file_output) else None
    _, candidate_offset, saved_transfer_id = (
        _find_resume_candidate(prelim_dir, known_lookup) if resume else (None, 0, "")
    )

    headers = {
        "X-LAN-PIN": clean_pin,
        "X-LAN-AUTH": get_client_auth_token(key_bytes),
    }
    if resume and candidate_offset > 0 and saved_transfer_id:
        headers["Range"] = f"bytes={candidate_offset}-"
        headers["X-LAN-TRANSFER-ID"] = saved_transfer_id

    part_path: str | None = None
    meta_path: str | None = None
    is_dir = False

    try:
        with requests.get(url, stream=True, headers=headers, timeout=(10, 30)) as response:
            if response.status_code == 403:
                reason = response.headers.get("X-LAN-REASON", "PIN")
                if not quiet:
                    if reason == "KEY":
                        console.print("\n[red][X] Access Denied: Incorrect Encryption Key.[/red]")
                    else:
                        console.print("\n[red][X] Access Denied: Incorrect Security PIN.[/red]")
                return False
            if response.status_code == 429:
                if not quiet:
                    console.print(
                        "\n[red][X] Access Blocked: Too many failed PIN attempts from this IP.[/red]"
                    )
                return False
            if response.status_code == 503:
                if not quiet:
                    console.print(
                        "\n[yellow][!] Server Busy: All download slots are currently in use or completed.[/yellow]"
                    )
                return False
            if response.status_code == 404:
                if not quiet:
                    console.print("\n[red][X] File or directory not found on sender.[/red]")
                return False

            response.raise_for_status()

            nonce_b64 = response.headers.get("X-LAN-NONCE")
            verify_hash_b64 = response.headers.get("X-LAN-VERIFY")
            is_dir = response.headers.get("X-LAN-ISDIR", "false").lower() == "true"
            server_filename_enc = response.headers.get("X-LAN-FILENAME", "")
            transfer_id = response.headers.get("X-LAN-TRANSFER-ID", "")

            if not nonce_b64:
                if not quiet:
                    console.print("\n[red][X] Protocol Error: Missing cryptographic nonce from sender.[/red]")
                return False

            try:
                nonce = base64.b64decode(nonce_b64, validate=True)
            except (binascii.Error, ValueError):
                if not quiet:
                    console.print("\n[red][X] Protocol Error: Invalid cryptographic nonce from sender.[/red]")
                return False

            if len(nonce) != CTR_NONCE_SIZE:
                if not quiet:
                    console.print("\n[red][X] Protocol Error: Unexpected nonce size.[/red]")
                return False

            # Verify AES key via HMAC BEFORE touching disk
            if verify_hash_b64 and not verify_key(key_bytes, verify_hash_b64):
                if not quiet:
                    console.print("\n[red][X] Access Denied: Incorrect Encryption Key.[/red]")
                return False

            raw_server_name = urllib.parse.unquote(server_filename_enc) if server_filename_enc else ""
            effective_default_name = cli_decoded_name or raw_server_name or "downloaded_file"
            dest_dir, target_filename = _determine_dest_dir_and_name(
                effective_default_name, output, extract=extract
            )
            os.makedirs(dest_dir, exist_ok=True)

            part_path = os.path.join(dest_dir, f"{target_filename}.part")
            meta_path = os.path.join(dest_dir, f"{target_filename}.part.meta")

            # Determine whether server accepted Range resume (206) or started fresh (200)
            resuming = False
            start_offset = 0
            if response.status_code == 206 and not is_dir:
                srv_offset = int(response.headers.get("X-LAN-OFFSET", "0"))
                if os.path.isfile(part_path) and os.path.getsize(part_path) == srv_offset and srv_offset > 0:
                    resuming = True
                    start_offset = srv_offset
                else:
                    if not quiet:
                        console.print(
                            "\n[red][X] Resume state mismatch; delete partial .part file and retry.[/red]"
                        )
                    return False

            decryptor = get_decryptor(key_bytes, nonce, byte_offset=start_offset)

            content_length_hdr = response.headers.get("Content-Length")
            expected_run_bytes = int(content_length_hdr) if content_length_hdr is not None else None

            if is_dir:
                est_hdr = response.headers.get("X-LAN-ESTIMATED-SIZE")
                progress_total = int(est_hdr) if (est_hdr and est_hdr.isdigit() and int(est_hdr) > 0) else None
            else:
                total_hdr = response.headers.get("X-LAN-TOTAL-SIZE")
                if total_hdr and total_hdr.isdigit():
                    progress_total = int(total_hdr)
                elif expected_run_bytes is not None:
                    progress_total = start_offset + expected_run_bytes
                else:
                    progress_total = None

            if resuming:
                if not quiet:
                    console.print(f"[cyan][*] Resuming download from {format_size(start_offset)}...[/cyan]")
                sha256_hasher = _hash_existing_file(part_path, start_offset)
                file_mode = "ab"
            else:
                sha256_hasher = hashlib.sha256()
                file_mode = "wb"
                if not is_dir and resume and transfer_id:
                    with open(meta_path, "w", encoding="utf-8") as mf:
                        json.dump({"transfer_id": transfer_id, "filename": target_filename}, mf)

            bytes_received = 0
            pbar = None
            if not quiet:
                pbar = tqdm(
                    desc="Decrypting",
                    initial=start_offset,
                    total=progress_total,
                    unit="iB",
                    unit_scale=True,
                    unit_divisor=1024,
                    bar_format="{l_bar}{bar:40}{r_bar}",
                    colour="cyan",
                )

            try:
                with open(part_path, file_mode) as file_out:
                    for data in response.iter_content(BLOCK_SIZE):
                        if not data:
                            continue
                        decrypted_chunk = decryptor.update(data)
                        sha256_hasher.update(decrypted_chunk)
                        file_out.write(decrypted_chunk)
                        bytes_received += len(data)

                        if pbar is not None:
                            if pbar.total is not None and (pbar.n + len(data)) > pbar.total:
                                pbar.total = pbar.n + len(data)
                            pbar.update(len(data))

                    tail = decryptor.finalize()
                    if tail:
                        sha256_hasher.update(tail)
                        file_out.write(tail)
                    file_out.flush()

                if pbar is not None and pbar.total is not None:
                    pbar.total = pbar.n
                    pbar.refresh()
            finally:
                if pbar is not None:
                    pbar.close()

            # Verify exact byte count for regular files before committing
            if not is_dir and expected_run_bytes is not None and bytes_received != expected_run_bytes:
                raise IOError(
                    f"Transfer truncated: received {bytes_received} of {expected_run_bytes} expected bytes."
                )

            final_path, was_renamed = resolve_output_path(
                target_filename,
                output=dest_dir + os.sep,
                overwrite=overwrite,
            )
            os.replace(part_path, final_path)
            _cleanup_files(meta_path)

            digest = sha256_hasher.hexdigest()
            if not quiet:
                console.print("\n[bold green][OK] Download completed successfully![/bold green]")
                if was_renamed:
                    console.print(
                        "[yellow][!] Existing file preserved; saved under a new name (use --overwrite to replace).[/yellow]"
                    )
                console.print(f"[i] Saved to: [dim]{final_path}[/dim]")
                console.print(f"[SEC] Verified SHA-256: [dim]{digest}[/dim]")

            if is_dir:
                if extract:
                    extracted_root = safe_extract_tar(final_path, dest_dir)
                    _cleanup_files(final_path)
                    if not quiet:
                        console.print(f"[bold green][OK] Extracted folder to:[/bold green] {extracted_root}")
                elif not quiet:
                    console.print(
                        "[yellow][i] Note: Received archive contains a folder. "
                        f"Extract with:[/yellow] [cyan]tar -xf \"{final_path}\"[/cyan] "
                        "[dim](or pass --extract / -x next time)[/dim]"
                    )

            return True

    except (requests.exceptions.RequestException, IOError, OSError) as exc:
        if not quiet:
            console.print(f"\n[red][X] Connection or transfer error:[/red] {exc}")
        _handle_interrupted_part(part_path, meta_path, is_dir=is_dir, resume=resume, quiet=quiet)
        return False
    except KeyboardInterrupt:
        if not quiet:
            console.print("\n[yellow][!] Download interrupted by user.[/yellow]")
        _handle_interrupted_part(part_path, meta_path, is_dir=is_dir, resume=resume, quiet=quiet)
        return False


def _handle_interrupted_part(
    part_path: str | None,
    meta_path: str | None,
    is_dir: bool,
    resume: bool,
    quiet: bool,
) -> None:
    if not part_path or not os.path.exists(part_path):
        _cleanup_files(meta_path)
        return

    try:
        partial_size = os.path.getsize(part_path)
    except OSError:
        partial_size = 0

    if is_dir or not resume or partial_size <= 0:
        _cleanup_files(part_path, meta_path)
    elif not quiet:
        console.print(
            f"[cyan][i] Partial progress saved ({format_size(partial_size)}). "
            f"Re-run the same command to resume![/cyan]"
        )
