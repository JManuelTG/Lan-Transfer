import argparse
import socket
import os
import sys
import requests
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel
import urllib.parse

console = Console()

def get_local_ip():
    """Gets the local IP of the computer on the LAN."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def send_file(filepath):
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        console.print(f"[red]Error: The file '{filepath}' does not exist or is invalid.[/red]")
        sys.exit(1)

    filename = os.path.basename(filepath)
    file_dir = os.path.dirname(os.path.abspath(filepath))

    # Generar credenciales de seguridad
    pin = str(secrets.randbelow(10000)).zfill(4)
    key_bytes = os.urandom(32)
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')

    # Custom Handler to serve only the requested file and hide logs
    class FileHandler(SimpleHTTPRequestHandler):
        def translate_path(self, path):
            return os.path.join(file_dir, filename)

        def log_message(self, format, *args):
            pass

        def send_head(self):
            path = self.translate_path(self.path)
            # PIN Authentication
            client_pin = self.headers.get('X-LAN-PIN')
            if client_pin != pin:
                self.send_error(403, "Access Denied: Incorrect PIN")
                return None
                
            try:
                f = open(path, 'rb')
            except OSError:
                self.send_error(404, "File not found")
                return None
            
            self.nonce = os.urandom(16)
            
            self.send_response(200)
            self.send_header("Content-type", self.guess_type(path))
            self.send_header("Content-Length", str(os.path.getsize(path)))
            self.send_header("X-LAN-NONCE", base64.b64encode(self.nonce).decode('utf-8'))
            self.end_headers()
            return f

        def do_GET(self):
            super().do_GET()
            # Notify the server that download finished
            self.server.file_downloaded = True

        def copyfile(self, source, outputfile):
            # Get real size for progress bar
            total_size = os.path.getsize(os.path.join(file_dir, filename))
            encryptor = Cipher(algorithms.AES(key_bytes), modes.CTR(self.nonce)).encryptor()
            
            with tqdm(
                desc="Uploading (Secure)",
                total=total_size,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
                bar_format="{l_bar}{bar:40}{r_bar}",
                colour="green"
            ) as pbar:
                # Copy in 1MB chunks and encrypt on the fly
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outputfile.write(encrypted_chunk)
                    pbar.update(len(chunk))

    server = TCPServer(("0.0.0.0", 0), FileHandler)
    server.file_downloaded = False
    # Timeout corto para que Python despierte y escuche el Ctrl+C
    server.timeout = 0.5
    
    ip = get_local_ip()
    port = server.server_address[1]

    # Codificar el nombre por si tiene espacios
    encoded_filename = urllib.parse.quote(filename)
    
    console.print(Panel.fit(
        f"[bold green]📡 File ready to send:[/bold green] {filename}\n"
        f"[bold yellow]Size:[/bold yellow] {os.path.getsize(filepath) / (1024*1024):.2f} MB\n"
        f"[bold red]🔒 Security PIN:[/bold red] {pin}\n\n"
        f"Go to the receiving computer and run the following command:\n\n"
        f"[bold cyan]lan-transfer receive {ip}:{port} {encoded_filename} --pin {pin} --key {key_b64}[/bold cyan]",
        title="[bold blue]LAN Transfer Shield - Sender Mode[/bold blue]"
    ))

    try:
        console.print("\n[dim]Waiting for receiver to connect... (Press Ctrl+C to cancel)[/dim]")
        # Loop with timeout to allow OS to register Ctrl+C on Windows
        while not server.file_downloaded:
            server.handle_request()
        console.print("\n[bold green]✅ Transfer complete. Server safely closed.[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Transfer cancelled by user.[/yellow]")
    finally:
        server.server_close()

def receive_file(address, filename, pin, key_b64):
    decoded_filename = urllib.parse.unquote(filename)
    url = f"http://{address}/{filename}"
    
    console.print(Panel.fit(
        f"[bold blue]⬇ Downloading (Secure):[/bold blue] {decoded_filename}\n"
        f"[bold yellow]From:[/bold yellow] {address}",
        title="[bold cyan]LAN Transfer Shield - Receiver Mode[/bold cyan]"
    ))
    
    try:
        # HTTP Request with PIN Header
        headers = {'X-LAN-PIN': pin}
        response = requests.get(url, stream=True, headers=headers)
        
        if response.status_code == 403:
            console.print("\n[red]❌ Access Denied: Incorrect PIN or Session Expired.[/red]")
            return
            
        response.raise_for_status()
        
        # Extract Nonce and setup Decryptor
        nonce_b64 = response.headers.get('X-LAN-NONCE')
        if not nonce_b64:
            console.print("\n[red]❌ Protocol Error: Sender did not provide cryptographic token.[/red]")
            return
            
        nonce = base64.b64decode(nonce_b64)
        key_bytes = base64.b64decode(key_b64)
        decryptor = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce)).decryptor()
        
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024 # 1 MB Blocks
        
        # Barra de progreso TQDM
        with open(decoded_filename, 'wb') as file, tqdm(
            desc="Decrypting",
            total=total_size_in_bytes,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
            bar_format="{l_bar}{bar:40}{r_bar}",
            colour="cyan"
        ) as progress_bar:
            for data in response.iter_content(block_size):
                decrypted_chunk = decryptor.update(data)
                file.write(decrypted_chunk)
                progress_bar.update(len(data))
                
        console.print(f"\n[bold green]✅ Download completed successfully![/bold green]")
        console.print(f"File saved to: [dim]{os.path.abspath(decoded_filename)}[/dim]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"\n[red]❌ Connection or download error:[/red] {e}")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Download cancelled by user.[/yellow]")
        # Delete corrupt partial file if cancelled
        if os.path.exists(decoded_filename):
            os.remove(decoded_filename)

def main():
    parser = argparse.ArgumentParser(
        description="LAN Transfer CLI - Ultra-fast and robust tool to transfer files between local PCs.",
        epilog="Examples:\n"
               "  Send:    lan-transfer send \"C:\\Path\\To\\Video.mp4\"\n"
               "  Receive: lan-transfer receive 192.168.1.5:54321 Video.mp4 --pin 1234 --key A8X2...",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Operation commands")
    
    # Sub-parser for Sending
    send_parser = subparsers.add_parser("send", help="Opens a temporary server and exposes the specified file for download.")
    send_parser.add_argument("filepath", type=str, help="Absolute or relative path of the file to send.")
    
    # Sub-parser for Receiving
    receive_parser = subparsers.add_parser("receive", help="Connects to a local sender and downloads a file showing progress.")
    receive_parser.add_argument("address", type=str, help="IP and Port of the sender (e.g. 192.168.1.5:8080).")
    receive_parser.add_argument("filename", type=str, help="The encoded filename given by the sender command.")
    receive_parser.add_argument("--pin", type=str, required=True, help="4-digit security PIN.")
    receive_parser.add_argument("--key", type=str, required=True, help="AES-256 key generated by the sender.")
    
    args = parser.parse_args()
    
    if args.command == "send":
        send_file(args.filepath)
    elif args.command == "receive":
        receive_file(args.address, args.filename, args.pin, args.key)
    else:
        # Si no pasan comando, mostramos el menú de ayuda
        parser.print_help()

if __name__ == "__main__":
    main()
