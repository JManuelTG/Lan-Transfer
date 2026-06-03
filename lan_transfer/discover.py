import time
import socket
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from rich.console import Console
from rich.table import Table

console = Console()

class LanTransferBroadcaster:
    def __init__(self, ip, port, filename):
        self.zeroconf = Zeroconf()
        self.info = ServiceInfo(
            "_http._tcp.local.",
            f"LAN-Transfer-{filename[:15]}._http._tcp.local.",
            addresses=[socket.inet_aton(ip)],
            port=port,
            properties={'filename': filename.encode('utf-8')},
            server=f"lan-transfer-{port}.local."
        )
        
    def start(self):
        self.zeroconf.register_service(self.info)
        
    def stop(self):
        self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()


class TransferListener:
    def __init__(self):
        self.services = []

    def remove_service(self, zeroconf, type, name):
        self.services = [s for s in self.services if s.name != name]

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            self.services.append(info)

    def update_service(self, zeroconf, type, name):
        pass


def discover_transfers():
    console.print("[cyan][*] Scanning local network for LAN Transfers...[/cyan]")
    zeroconf = Zeroconf()
    listener = TransferListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    
    try:
        time.sleep(3) # Scan for 3 seconds
    finally:
        zeroconf.close()
        
    lan_services = [s for s in listener.services if s.name.startswith("LAN-Transfer-")]
    
    if not lan_services:
        console.print("[yellow]No active LAN Transfers found on the network.[/yellow]")
        return
        
    table = Table(title="Available LAN Transfers")
    table.add_column("ID", style="cyan")
    table.add_column("File Name", style="green")
    table.add_column("Sender IP:Port", style="magenta")
    
    for i, svc in enumerate(lan_services):
        ip = socket.inet_ntoa(svc.addresses[0])
        port = svc.port
        filename = svc.properties.get(b'filename', b'').decode('utf-8')
        table.add_row(str(i+1), filename, f"{ip}:{port}")
        
    console.print(table)
    
    try:
        choice = input("\nEnter the ID of the transfer to download (or press Enter to exit): ")
        if not choice.strip() or not choice.isdigit():
            return
            
        choice = int(choice)
        if choice < 1 or choice > len(lan_services):
            console.print("[red]Invalid ID.[/red]")
            return
            
        svc = lan_services[choice - 1]
        ip = socket.inet_ntoa(svc.addresses[0])
        port = svc.port
        filename = svc.properties.get(b'filename', b'').decode('utf-8')
        
        pin = input(f"Enter the 4-digit PIN for '{filename}': ").strip()
        key_b64 = input(f"Enter the encryption Key for '{filename}': ").strip()
        
        # Now we launch the receiver
        from .receiver import receive_file
        import urllib.parse
        encoded_filename = urllib.parse.quote(filename)
        console.print("\n")
        receive_file(f"{ip}:{port}", encoded_filename, pin, key_b64)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Discovery cancelled.[/yellow]")
