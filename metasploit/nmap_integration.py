import nmap

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_network(self, target):
        """Escaneia uma rede ou host."""
        return self.scanner.scan(target, arguments='-sV')