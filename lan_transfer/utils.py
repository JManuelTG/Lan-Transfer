from __future__ import annotations

import ipaddress
import os
import re
import socket
import tarfile

_VIRTUAL_ADAPTER_KEYWORDS = (
    "vethernet",
    "wsl",
    "hyper-v",
    "docker",
    "vbox",
    "virtualbox",
    "vmware",
    "loopback",
    "teredo",
    "isatap",
)

_WINDOWS_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _is_usable_lan_ipv4(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified)


def get_all_local_ips(include_virtual: bool = True) -> list[str]:
    """Returns usable local IPv4 addresses prioritized for physical LAN interfaces."""
    primary_candidates: list[str] = []
    secondary_candidates: list[str] = []

    try:
        import ifaddr

        for adapter in ifaddr.get_adapters():
            adapter_name = f"{adapter.name} {adapter.nice_name}".lower()
            is_virtual = any(k in adapter_name for k in _VIRTUAL_ADAPTER_KEYWORDS)
            for ip_info in adapter.ips:
                if isinstance(ip_info.ip, str) and _is_usable_lan_ipv4(ip_info.ip):
                    target = secondary_candidates if is_virtual else primary_candidates
                    if ip_info.ip not in target:
                        target.append(ip_info.ip)
    except Exception:
        pass

    # Fallback via hostname resolution if ifaddr yielded nothing
    if not primary_candidates and not secondary_candidates:
        try:
            _, _, host_ips = socket.gethostbyname_ex(socket.gethostname())
            for ip_str in host_ips:
                if _is_usable_lan_ipv4(ip_str) and ip_str not in primary_candidates:
                    primary_candidates.append(ip_str)
        except Exception:
            pass

    if not include_virtual:
        return primary_candidates
    return primary_candidates + [ip for ip in secondary_candidates if ip not in primary_candidates]


def get_local_ip() -> str:
    """Gets the best local LAN IPv4 address of this computer, working even without internet."""
    physical_ips = get_all_local_ips(include_virtual=False)

    # Attempt standard OS routing table lookup via UDP connect (sends no packets)
    for probe_target in (("192.168.1.1", 80), ("10.255.255.255", 1), ("8.8.8.8", 80)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(probe_target)
            ip = s.getsockname()[0]
            if _is_usable_lan_ipv4(ip):
                if physical_ips and ip not in physical_ips:
                    return physical_ips[0]
                return ip
        except Exception:
            continue
        finally:
            s.close()

    all_ips = get_all_local_ips(include_virtual=True)
    if all_ips:
        return all_ips[0]

    return "127.0.0.1"


def format_size(num_bytes: int) -> str:
    """Formats a byte count into a human-readable string."""
    if num_bytes < 0:
        return "Unknown"
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} TB"


def sanitize_filename(filename: str) -> str:
    """Sanitizes an untrusted filename to prevent path traversal and invalid OS characters."""
    normalized = filename.replace("\\", "/").strip()
    base = os.path.basename(normalized)
    # Strip Windows drive prefixes if any slipped through (e.g., "C:evil.txt")
    if len(base) >= 2 and base[1] == ":":
        base = base[2:]
    base = _WINDOWS_INVALID_CHARS.sub("_", base).strip(" .")
    if not base or base in (".", ".."):
        return "downloaded_file"
    return base


def _split_filename_ext(filename: str) -> tuple[str, str]:
    """Splits filename into stem and extension, preserving compound tar extensions."""
    lower = filename.lower()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound) and len(filename) > len(compound):
            return filename[: -len(compound)], filename[-len(compound) :]
    return os.path.splitext(filename)


def resolve_output_path(filename: str, output: str | None = None, overwrite: bool = False) -> tuple[str, bool]:
    """
    Determines the safe destination path for a received file.
    Returns (resolved_path, was_renamed).
    """
    safe_name = sanitize_filename(filename)

    if output:
        expanded = os.path.abspath(os.path.expanduser(output))
        has_ext = bool(os.path.splitext(os.path.basename(expanded))[1])
        is_dir_target = (
            os.path.isdir(expanded)
            or output.endswith(("/", "\\"))
            or (not os.path.exists(expanded) and not has_ext)
        )
        if is_dir_target:
            os.makedirs(expanded, exist_ok=True)
            candidate = os.path.join(expanded, safe_name)
        else:
            parent = os.path.dirname(expanded)
            if parent:
                os.makedirs(parent, exist_ok=True)
            candidate = expanded
    else:
        candidate = os.path.abspath(safe_name)

    if overwrite or not os.path.exists(candidate):
        return candidate, False

    directory = os.path.dirname(candidate)
    base_name = os.path.basename(candidate)
    stem, ext = _split_filename_ext(base_name)

    counter = 1
    while True:
        alt_path = os.path.join(directory, f"{stem} ({counter}){ext}")
        if not os.path.exists(alt_path):
            return alt_path, True
        counter += 1


def safe_extract_tar(tar_path: str, extract_dir: str) -> str:
    """
    Safely extracts a .tar or .tar.gz archive into extract_dir,
    blocking path traversal (TarSlip), absolute paths, and unsafe links.
    Returns the top-level extracted path.
    """
    abs_extract_dir = os.path.abspath(extract_dir)
    os.makedirs(abs_extract_dir, exist_ok=True)

    with tarfile.open(tar_path, mode="r:*") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=abs_extract_dir, filter="data")
        else:
            safe_members = []
            for member in tar.getmembers():
                member_path = os.path.abspath(os.path.join(abs_extract_dir, member.name))
                if os.path.commonpath([abs_extract_dir, member_path]) != abs_extract_dir:
                    raise ValueError(f"Unsafe path in archive blocked: {member.name}")
                if member.ischr() or member.isblk() or member.isfifo():
                    continue
                if member.issym() or member.islnk():
                    link_base = os.path.dirname(member_path) if member.issym() else abs_extract_dir
                    link_target = os.path.abspath(os.path.join(link_base, member.linkname))
                    if os.path.commonpath([abs_extract_dir, link_target]) != abs_extract_dir:
                        raise ValueError(f"Unsafe link in archive blocked: {member.name}")
                safe_members.append(member)
            tar.extractall(path=abs_extract_dir, members=safe_members)

        members = tar.getnames()
        if members:
            top = members[0].split("/")[0].split("\\")[0]
            if top:
                return os.path.join(abs_extract_dir, top)
    return abs_extract_dir
