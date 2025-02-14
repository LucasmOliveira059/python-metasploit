import nmap
import queue
import threading
import dns.resolver

class NmapScanner:
    def __init__(self):
        """Inicializa o scanner Nmap."""
        self.scanner = nmap.PortScanner()

    def scan_hosts(scanNmap):
        """
        Função para escanear hosts e retornar informações como portas, serviços, estado e endereço MAC.

        Parâmetros:
            scanNmap: Objeto retornado pelo Nmap contendo os resultados do scan.

        Retorno:
            Uma lista de dicionários contendo informações sobre cada host.
        """
        resultados = []

        for host in scanNmap.all_hosts():
            info_host = {
                "host": host,
                "estado": scanNmap[host]['status']['state'],
                "portas": [],
                "enderecoMAC": None,
                "fabricante": None
            }

            for protocolo in scanNmap[host].all_protocols():
                for porta in scanNmap[host][protocolo]:
                    alvo = scanNmap[host][protocolo][porta]
                    info_host["portas"].append({
                        "porta": porta,
                        "protocolo": protocolo,
                        "estado": alvo['state'],
                        "servico": alvo['name']
                    })

            enderecoMAC = scanNmap[host]["addresses"].get("mac", "Desconhecido")
            info_host["enderecoMAC"] = enderecoMAC
            if enderecoMAC != "Desconhecido":
                info_host["fabricante"] = scanNmap[host]['vendor'].get(enderecoMAC, "Desconhecido")

            resultados.append(info_host)

        return resultados

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

    def mapear_subdominios(dominio, arquivo_subdominios, num_threads=20):
        """
        Função para mapear subdomínios de um domínio principal usando consultas DNS paralelas.

        Parâmetros:
            dominio (str): O domínio principal (ex: "blogspot.com").
            arquivo_subdominios (str): Caminho do arquivo contendo a lista de subdomínios.
            num_threads (int): Número de threads para processamento paralelo (padrão: 20).

        Retorno:
            Um dicionário contendo os resultados das consultas DNS para cada subdomínio.
        """
        registros = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
        q = queue.Queue()
        resultados = {}

        def consultar_dns():
            while True:
                try:
                    subdominio = q.get(timeout=5)
                    DNS = f"{subdominio}.{dominio}"
                    resultados[DNS] = {}

                    for registro in registros:
                        try:
                            resposta = dns.resolver.resolve(DNS, registro, raise_on_no_answer=False)
                            if resposta.rrset:
                                resultados[DNS][registro] = [str(dado) for dado in resposta]
                        except dns.resolver.NXDOMAIN:
                            resultados[DNS][registro] = "Domínio não existe"
                        except dns.resolver.NoAnswer:
                            resultados[DNS][registro] = "Nenhum registro encontrado"
                        except Exception as e:
                            resultados[DNS][registro] = f"Erro: {e}"

                    q.task_done()
                except queue.Empty:
                    break

        for i in range(num_threads):
            t = threading.Thread(target=consultar_dns)
            t.daemon = True
            t.start()

        with open(arquivo_subdominios) as lista:
            for nome in lista:
                nome = nome.strip("\n")
                if nome:
                    q.put(nome)

        q.join()
        return resultados
