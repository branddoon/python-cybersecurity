from scapy.all import ARP, Ether, srp
from rich.progress import track
from rich.table import Table
from rich.console import Console

class ARPScan():

    def __init__(self, network):
        self.network = network
        self.timeout = 1
    
    #----- Method scans all network by sending ARP packets-----#
    def scan_devices_by_ARP(self):
        print("Starting ARP scanning")
        packet = Ether(dst = "ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network)
        result = srp(packet, self.timeout, verbose=0)[0]
        devices = []
        for sent, received in track (result, description="Processing devices by ARP..."):
            devices.append({'ip':received.psrc, 'mac':received.hwsrc})
        print("Finished ARP scanning")
        return devices
    
    #----- Method that prints visual table -----#
    def show_table(self, data, type):
        table = Table(title="Network ARP scanning")
        console = Console()
        if type == "hosts_arp":
            table.add_column("IP Address", style="bold green")
            table.add_column("MAC", style="bold blue")
            for element in data:
                table.add_row(element['ip'], element['mac'])
        console.print(table)


if __name__ == '__main__':
    arp_scan = ARPScan("192.168.1.0/24")
    data = arp_scan.scan_devices_by_ARP()
    arp_scan.show_table(data, "hosts_arp")
