import os
import sys
import base64
import tarfile
import threading
from io import BytesIO
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel
import urllib.parse
from .utils import get_local_ip
from .crypto import generate_credentials, get_encryptor
from .discover import LanTransferBroadcaster

console = Console()

import queue

class TarStreamer:
    """A file-like object that streams a folder as a TAR archive block by block without loading into RAM."""
    def __init__(self, directory):
        self.directory = directory
        self.q = queue.Queue(maxsize=50) # Allow up to 50MB in queue
        self.thread = threading.Thread(target=self._build_tar)
        self.total_size = self._calculate_total_size()
        self.buffer = b""
        self._write_buffer = bytearray()
        self.thread.start()
        
    def _calculate_total_size(self):
        total = 0
        for root, _, files in os.walk(self.directory):
            for f in files:
                total += os.path.getsize(os.path.join(root, f))
        return int(total * 1.01)

    def write(self, b):
        self._write_buffer.extend(b)
        if len(self._write_buffer) >= 1024 * 1024: # Buffer up to 1MB before passing to queue
            self.q.put(bytes(self._write_buffer))
            self._write_buffer = bytearray()
        
    def flush(self):
        pass

    def _build_tar(self):
        try:
            with tarfile.open(fileobj=self, mode="w|") as tar:
                tar.add(self.directory, arcname=os.path.basename(os.path.abspath(self.directory)))
        except Exception as e:
            console.print(f"[red][X] Error creating TAR stream: {e}[/red]")
        finally:
            if self._write_buffer:
                self.q.put(bytes(self._write_buffer))
            self.q.put(None)

    def read(self, size=-1):
        if getattr(self, "exhausted", False):
            return b""
            
        data = bytearray()
        
        while size == -1 or len(data) < size:
            if not self.buffer:
                chunk = self.q.get()
                if chunk is None:
                    self.exhausted = True
                    break
                self.buffer = chunk
                
            needed = size - len(data) if size != -1 else len(self.buffer)
            data.extend(self.buffer[:needed])
            self.buffer = self.buffer[needed:]
            
        return bytes(data)

    def close(self):
        """Called by HTTP server when done."""
        pass


def send_file(filepath, users=1):
    is_dir = os.path.isdir(filepath)
    if not os.path.exists(filepath):
        console.print(f"[red]Error: The path '{filepath}' does not exist.[/red]")
        sys.exit(1)

    filename = os.path.basename(os.path.abspath(filepath))
    if is_dir:
        filename += ".tar"
        
    file_dir = os.path.dirname(os.path.abspath(filepath))

    pin, key_bytes, key_b64 = generate_credentials()

    class FileHandler(SimpleHTTPRequestHandler):
        def translate_path(self, path):
            if is_dir:
                return os.path.abspath(filepath)
            return os.path.join(file_dir, filename)

        def log_message(self, format, *args):
            pass

        def send_head(self):
            path = self.translate_path(self.path)
            
            client_pin = self.headers.get('X-LAN-PIN')
            if client_pin != pin:
                self.send_error(403, "Access Denied: Incorrect PIN")
                return None
                
            if not is_dir and not os.path.exists(path):
                self.send_error(404, "File not found")
                return None
            
            self.nonce = os.urandom(16)
            self.send_response(200)
            
            if is_dir:
                self.send_header("Content-type", "application/x-tar")
                # We can't know exact TAR size precisely, send generic stream header
                # We remove Content-Length for directories to allow chunked/stream reading
            else:
                self.send_header("Content-type", self.guess_type(path))
                self.send_header("Content-Length", str(os.path.getsize(path)))
                
            self.send_header("X-LAN-NONCE", base64.b64encode(self.nonce).decode('utf-8'))
            self.send_header("X-LAN-ISDIR", str(is_dir).lower())
            
            from .crypto import get_key_verification_hash
            self.send_header("X-LAN-VERIFY", get_key_verification_hash(key_bytes))
            
            self.end_headers()
            
            if is_dir:
                return TarStreamer(path)
            else:
                return open(path, 'rb')

        def do_GET(self):
            super().do_GET()
            self.server.downloads_remaining -= 1

        def copyfile(self, source, outputfile):
            encryptor = get_encryptor(key_bytes, self.nonce)
            
            if is_dir:
                total_size = source.total_size
            else:
                total_size = os.path.getsize(os.path.join(file_dir, filename))
                
            with tqdm(
                desc=f"Uploading (Secure) - Users Left: {self.server.downloads_remaining}",
                total=total_size,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
                bar_format="{l_bar}{bar:40}{r_bar}",
                colour="green"
            ) as pbar:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outputfile.write(encrypted_chunk)
                    pbar.update(len(chunk))

    server = TCPServer(("0.0.0.0", 0), FileHandler)
    server.downloads_remaining = users
    server.timeout = 0.5
    
    ip = get_local_ip()
    port = server.server_address[1]

    encoded_filename = urllib.parse.quote(filename)
    
    if is_dir:
        size_display = "Unknown (Streaming Directory)"
    else:
        size_display = f"{os.path.getsize(filepath) / (1024*1024):.2f} MB"

    console.print(Panel.fit(
        f"[bold green][*] Ready to send:[/bold green] {filename} ({users} max downloads)\n"
        f"[bold yellow][i] Size:[/bold yellow] {size_display}\n"
        f"[bold red][SEC] Security PIN:[/bold red] {pin}\n\n"
        f"Receiver command:\n\n"
        f"[bold cyan]lan-transfer receive {ip}:{port} {encoded_filename} --pin {pin} --key {key_b64}[/bold cyan]",
        title="[bold blue]LAN Transfer Shield - Sender Mode[/bold blue]"
    ))
    
    broadcaster = LanTransferBroadcaster(ip, port, filename)
    broadcaster.start()

    try:
        console.print("\n[dim]Waiting for receivers to connect... (Press Ctrl+C to cancel)[/dim]")
        while server.downloads_remaining > 0:
            server.handle_request()
        console.print("\n[bold green][OK] All transfers complete. Server safely closed.[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Transfer cancelled by user.[/yellow]")
    finally:
        broadcaster.stop()
        server.server_close()
