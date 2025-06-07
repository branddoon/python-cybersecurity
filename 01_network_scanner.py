from scapy.all import ARP, Ether, srp
from rich.progress import track
from rich.table import Table
from rich.console import Console

class NetworkScanner:

    def __init__(self, target):
        self.target = target

    #----- Method that executes ARP scanning in local newtork, done by scapy -----#
    def scan_arp(self):
        arp_request = Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = self.target)
        results, _ = srp(arp_request, timeout=1, verbose=False)
        client_list =[]
        for query, answer in track(results, description="Processing packages..."):
            client_list.append({f'IP': str(answer.psrc), f'MAC': str(answer.hwsrc)})
        return client_list
    
    #----- Method that prints visual table -----#
    def show_table(self, data, type):
        if type == "hosts":
            table = Table(title="Network ARP scanning")
            table.add_column("IP", style="bright_blue")
            table.add_column("MAC", style="dark_cyan")
            for host in data:
                table.add_row(host.get('IP'), host.get('MAC'))
            console = Console()
            console.print(table)

if __name__ == '__main__':
    print('Stating network scanning')
    network_scanner = NetworkScanner("192.168.238.0/24")
    client_list = network_scanner.scan_arp()
    network_scanner.show_table(client_list, "hosts")
    print('Finished network scanning')