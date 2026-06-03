import argparse
import socket
import os
import sys
import requests
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel
import urllib.parse

console = Console()

def get_local_ip():
    """Obtiene la IP local de la computadora en la red LAN."""
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
        console.print(f"[red]Error: El archivo '{filepath}' no existe o no es válido.[/red]")
        sys.exit(1)

    filename = os.path.basename(filepath)
    file_dir = os.path.dirname(os.path.abspath(filepath))

    # Handler personalizado para servir únicamente el archivo solicitado y ocultar logs
    class FileHandler(SimpleHTTPRequestHandler):
        def translate_path(self, path):
            return os.path.join(file_dir, filename)

        def log_message(self, format, *args):
            pass

        def do_GET(self):
            super().do_GET()
            # Avisamos al servidor que la descarga ha terminado
            self.server.file_downloaded = True

        def copyfile(self, source, outputfile):
            # Obtenemos el tamaño real para la barra de progreso
            total_size = os.path.getsize(os.path.join(file_dir, filename))
            with tqdm(
                desc="Subiendo",
                total=total_size,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
                bar_format="{l_bar}{bar:40}{r_bar}",
                colour="green"
            ) as pbar:
                # Copiamos en chunks de 1MB para reportar progreso
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    outputfile.write(chunk)
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
        f"[bold green]📡 Archivo listo para enviar:[/bold green] {filename}\n"
        f"[bold yellow]Tamaño:[/bold yellow] {os.path.getsize(filepath) / (1024*1024):.2f} MB\n\n"
        f"Ve a la computadora receptora y ejecuta el siguiente comando:\n\n"
        f"[bold cyan]lan-transfer receive {ip}:{port} {encoded_filename}[/bold cyan]",
        title="[bold blue]LAN Transfer - Modo Emisor[/bold blue]"
    ))

    try:
        console.print("\n[dim]Esperando conexión del receptor... (Presiona Ctrl+C para cancelar)[/dim]")
        # Loop con timeout para permitir que el SO registre el Ctrl+C en Windows
        while not server.file_downloaded:
            server.handle_request()
        console.print("\n[bold green]✅ Transferencia completada. El servidor se ha cerrado por seguridad.[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Transferencia cancelada por el usuario.[/yellow]")
    finally:
        server.server_close()

def receive_file(address, filename):
    decoded_filename = urllib.parse.unquote(filename)
    url = f"http://{address}/{filename}"
    
    console.print(Panel.fit(
        f"[bold blue]⬇ Descargando:[/bold blue] {decoded_filename}\n"
        f"[bold yellow]Desde:[/bold yellow] {address}",
        title="[bold cyan]LAN Transfer - Modo Receptor[/bold cyan]"
    ))
    
    try:
        # Hacemos la petición HTTP en modo stream para no colapsar la RAM
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024 # Bloques de 1 MB
        
        # Barra de progreso TQDM
        with open(decoded_filename, 'wb') as file, tqdm(
            desc="Progreso",
            total=total_size_in_bytes,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
            bar_format="{l_bar}{bar:40}{r_bar}",
            colour="cyan"
        ) as progress_bar:
            for data in response.iter_content(block_size):
                progress_bar.update(len(data))
                file.write(data)
                
        console.print(f"\n[bold green]✅ ¡Descarga completada con éxito![/bold green]")
        console.print(f"Archivo guardado en: [dim]{os.path.abspath(decoded_filename)}[/dim]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"\n[red]❌ Error al conectar o descargar:[/red] {e}")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Descarga cancelada por el usuario.[/yellow]")
        # Eliminar archivo corrupto parcial si se cancela
        if os.path.exists(decoded_filename):
            os.remove(decoded_filename)

def main():
    parser = argparse.ArgumentParser(
        description="LAN Transfer CLI - Herramienta ultrarrápida y robusta para transferir archivos entre PCs locales.",
        epilog="Ejemplos:\n"
               "  Emitir:  lan-transfer send \"C:\\Ruta\\Al\\Video.mp4\"\n"
               "  Recibir: lan-transfer receive 192.168.1.5:54321 Video.mp4",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos de operación")
    
    # Sub-parser para Enviar
    send_parser = subparsers.add_parser("send", help="Abre un servidor temporal y expone el archivo especificado para ser descargado.")
    send_parser.add_argument("filepath", type=str, help="La ruta absoluta o relativa del archivo que deseas enviar.")
    
    # Sub-parser para Recibir
    receive_parser = subparsers.add_parser("receive", help="Se conecta a un emisor local y descarga un archivo mostrando el progreso.")
    receive_parser.add_argument("address", type=str, help="La IP y Puerto del emisor (Ej. 192.168.1.5:8080).")
    receive_parser.add_argument("filename", type=str, help="El nombre codificado del archivo que te dio el comando emisor.")
    
    args = parser.parse_args()
    
    if args.command == "send":
        send_file(args.filepath)
    elif args.command == "receive":
        receive_file(args.address, args.filename)
    else:
        # Si no pasan comando, mostramos el menú de ayuda
        parser.print_help()

if __name__ == "__main__":
    main()
