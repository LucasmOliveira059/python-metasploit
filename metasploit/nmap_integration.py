import nmap

class NmapScanner:
    def __init__(self):
        """Inicializa o scanner Nmap."""
        self.scanner = nmap.PortScanner()

    def scan_host(self, target, arguments="-sV"):
        """
        Escaneia um host ou rede com o Nmap.

        :param target: Endereço IP ou range de IPs a ser escaneado (ex: '192.168.1.1' ou '192.168.1.0/24').
        :param arguments: Argumentos do Nmap (padrão: '-sV' para detecção de versão).
        :return: Resultado do scan no formato do Nmap.
        """
        print(f"Iniciando escaneamento do alvo: {target}")
        self.scanner.scan(target, arguments=arguments)
        return self.scanner[target]

    def list_open_ports(self, target):
        """
        Lista as portas abertas de um host escaneado.

        :param target: Endereço IP do host escaneado.
        :return: Lista de portas abertas.
        """
        if target not in self.scanner.all_hosts():
            raise ValueError(f"Host {target} não foi escaneado ou não foi encontrado.")

        open_ports = []
        for proto in self.scanner[target].all_protocols():
            ports = self.scanner[target][proto].keys()
            for port in ports:
                if self.scanner[target][proto][port]['state'] == 'open':
                    open_ports.append(port)
        return open_ports

    def get_service_info(self, target, port):
        """
        Obtém informações sobre um serviço específico em um host escaneado.

        :param target: Endereço IP do host escaneado.
        :param port: Porta a ser consultada.
        :return: Informações sobre o serviço.
        """
        if target not in self.scanner.all_hosts():
            raise ValueError(f"Host {target} não foi escaneado ou não foi encontrado.")

        for proto in self.scanner[target].all_protocols():
            if port in self.scanner[target][proto]:
                return self.scanner[target][proto][port]
        raise ValueError(f"Porta {port} não encontrada no host {target}.")