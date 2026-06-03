import os
import tarfile
import urllib.parse
import requests
import base64
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel
from .crypto import get_decryptor

console = Console()

def receive_file(address, filename, pin, key_b64):
    decoded_filename = urllib.parse.unquote(filename)
    url = f"http://{address}/{filename}"
    
    console.print(Panel.fit(
        f"[bold blue][v] Downloading (Secure):[/bold blue] {decoded_filename}\n"
        f"[bold yellow]From:[/bold yellow] {address}",
        title="[bold cyan]LAN Transfer Shield - Receiver Mode[/bold cyan]"
    ))
    
    try:
        headers = {'X-LAN-PIN': pin}
        response = requests.get(url, stream=True, headers=headers)
        
        if response.status_code == 403:
            console.print("\n[red][X] Access Denied: Incorrect PIN or Session Expired.[/red]")
            return
            
        response.raise_for_status()
        
        nonce_b64 = response.headers.get('X-LAN-NONCE')
        verify_hash_b64 = response.headers.get('X-LAN-VERIFY')
        is_dir = response.headers.get('X-LAN-ISDIR', 'false') == 'true'
        
        if not nonce_b64:
            console.print("\n[red][X] Protocol Error: Sender did not provide cryptographic token.[/red]")
            return
            
        nonce = base64.b64decode(nonce_b64)
        key_bytes = base64.b64decode(key_b64)
        
        # Verify the key using HMAC before downloading garbage
        from .crypto import verify_key
        if verify_hash_b64 and not verify_key(key_bytes, verify_hash_b64):
            console.print("\n[red][X] Access Denied: Incorrect Encryption Key.[/red]")
            return
            
        decryptor = get_decryptor(key_bytes, nonce)
        
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024
        
        # If it's a directory (tar), we can stream the decrypted data directly into tarfile extraction, 
        # but the easiest safe way is to download the .tar and then extract it.
        # Alternatively, we just save the .tar file for the user.
        # Let's just save the .tar file for the user to extract safely.
        
        with open(decoded_filename, 'wb') as file, tqdm(
            desc="Decrypting",
            total=total_size_in_bytes if total_size_in_bytes > 0 else None,
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
                
        console.print(f"\n[bold green][OK] Download completed successfully![/bold green]")
        console.print(f"File saved to: [dim]{os.path.abspath(decoded_filename)}[/dim]")
        
        if is_dir:
            console.print("[yellow]Note: The received file is a .tar archive containing the sent folder.[/yellow]")
            console.print(f"You can extract it using: [cyan]tar -xf \"{decoded_filename}\"[/cyan]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"\n[red][X] Connection or download error:[/red] {e}")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Download cancelled by user.[/yellow]")
        if os.path.exists(decoded_filename):
            os.remove(decoded_filename)
