# LAN Transfer CLI

An ultra-fast, zero-configuration command-line tool to transfer files and folders directly between computers on your local network (LAN) over an encrypted P2P HTTP/1.1 stream.

## Key Features
- **Direct LAN Speed:** Streams in 1 MiB blocks directly over TCP without intermediate cloud relays or temporary disk files.
- **End-to-End Encryption & Integrity:** On-the-fly **AES-256-CTR** stream encryption, **HMAC-SHA256** pre-flight key verification, constant-time **PIN authentication** with brute-force IP lockout, and automatic **SHA-256** checksum verification.
- **Zero-RAM Folder Streaming:** Send entire directories (`lan-transfer send ./MyFolder`) streamed dynamically as `.tar` or fast-compressed `.tar.gz` (`--compress`) and optionally unpacked automatically on receipt (`--extract`) with TarSlip path-traversal protection.
- **Automatic Resumable Downloads:** Interrupted large file transfers save progress in `.part` files and seamlessly resume from the exact byte offset using HTTP `Range` requests and AES-CTR counter seeking.
- **Multiplayer Mode (`--users N`):** Concurrent multi-threaded server stays open until `N` complete downloads succeed (failed or aborted attempts never waste download slots).
- **Network Radar (`discover`):** Zero-config mDNS (`zeroconf`) scanner discovers active transfers on your local Wi-Fi/Ethernet network showing file name, type, size, and sender address.

## Installation

### Portable Windows Executable
Copy **`dist/lan-transfer.exe`** to any Windows PC or USB drive—no Python installation required.
*(To rebuild from source on Windows, run `build.bat`).*

### From Source (Windows / Linux / macOS)
```bash
pip install .
```

## Usage

### 1. Send a File or Folder
```bash
# Send a single file (closes automatically after 1 completed download)
lan-transfer send "C:\Path\To\Video.mp4"

# Share with up to 3 concurrent receivers and auto-expire after 15 idle minutes
lan-transfer send "C:\Path\To\Dataset.zip" --users 3 --expire 15

# Stream a folder with fast on-the-fly gzip compression (.tar.gz)
lan-transfer send "C:\Path\To\ProjectFolder" --compress
```

### 2. Receive a File or Folder
Paste the command printed by the sender (filename is optional and auto-detected if omitted):
```bash
# Standard download (automatically resumes if previously interrupted)
lan-transfer receive 192.168.1.5:54321 Video.mp4 --pin 1234 --key <BASE64_KEY>

# Receive a folder into ./Downloads and automatically extract it
lan-transfer receive 192.168.1.5:54321 --pin 1234 --key <BASE64_KEY> -x -o ./Downloads
```

### 3. Discover Active Transfers on the LAN
```bash
lan-transfer discover
```

## Running Tests
```bash
python -m unittest discover -s tests -v
```
