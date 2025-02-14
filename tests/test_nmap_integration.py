import unittest
from unittest.mock import MagicMock, patch
from metasploit import NmapScanner  # Substitua pelo nome do seu módulo

class TestNmapScanner(unittest.TestCase):
    @patch('nmap.PortScanner')
    def test_scan_hosts(self, mock_port_scanner):
        # Simular o objeto scanNmap
        scanNmap = MagicMock()

        # Configurar os dados simulados
        scanNmap.all_hosts.return_value = ["192.168.1.1"]

        # Simular o comportamento de scanNmap["192.168.1.1"]
        host_mock = MagicMock()
        host_mock.all_protocols.return_value = ['tcp']
        host_mock.__getitem__.side_effect = lambda key: {
            'status': {'state': 'up'},
            'addresses': {'mac': '00:11:22:33:44:55'},
            'vendor': {'00:11:22:33:44:55': 'FabricanteX'},
            'tcp': {
                80: {'state': 'open', 'name': 'http'},
                443: {'state': 'open', 'name': 'https'}
            }
        }.get(key, {})

        scanNmap.__getitem__.return_value = host_mock

        # Configurar o mock do PortScanner para retornar o scanNmap simulado
        mock_port_scanner.return_value = scanNmap

        # Chamar a função scan_hosts
        resultados = NmapScanner.scan_hosts(scanNmap)

        # Verificar os resultados
        self.assertEqual(len(resultados), 1)  # Deve haver 1 host no resultado

        host_info = resultados[0]
        self.assertEqual(host_info["host"], "192.168.1.1")
        self.assertEqual(host_info["estado"], "up")
        self.assertEqual(host_info["enderecoMAC"], "00:11:22:33:44:55")
        self.assertEqual(host_info["fabricante"], "FabricanteX")

        # Verificar as portas
        self.assertEqual(len(host_info["portas"]), 2)
        self.assertEqual(host_info["portas"][0], {
            "porta": 80,
            "protocolo": "tcp",
            "estado": "open",
            "servico": "http"
        })
        self.assertEqual(host_info["portas"][1], {
            "porta": 443,
            "protocolo": "tcp",
            "estado": "open",
            "servico": "https"
        })


    @patch('nmap.PortScanner')
    def test_scan_hosts_sem_mac(self, mock_port_scanner):
        # Simular o objeto scanNmap
        scanNmap = MagicMock()

        # Configurar os dados simulados
        scanNmap.all_hosts.return_value = ["192.168.1.2"]

        # Simular o comportamento de scanNmap["192.168.1.2"]
        host_mock = MagicMock()
        host_mock.all_protocols.return_value = ['tcp']
        host_mock.__getitem__.side_effect = lambda key: {
            'status': {'state': 'up'},
            'addresses': {},  # Sem endereço MAC
            'vendor': {},  # Sem fabricante
            'tcp': {
                22: {'state': 'open', 'name': 'ssh'}
            }
        }.get(key, {})

        scanNmap.__getitem__.return_value = host_mock

        # Configurar o mock do PortScanner para retornar o scanNmap simulado
        mock_port_scanner.return_value = scanNmap

        # Chamar a função scan_hosts
        resultados = NmapScanner.scan_hosts(scanNmap)

        # Verificar os resultados
        self.assertEqual(len(resultados), 1)

        host_info = resultados[0]
        self.assertEqual(host_info["enderecoMAC"], "Desconhecido")
        self.assertEqual(host_info["fabricante"], None)

    @patch('nmap.PortScanner')
    def test_list_open_ports(self, mock_port_scanner):
        # Configura o mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]

        # Simula o objeto retornado por self.scanner[target]
        mock_host_result = MagicMock()
        mock_host_result.all_protocols.return_value = ["tcp"]
        mock_host_result.__getitem__.return_value = {80: {"state": "open"}, 443: {"state": "closed"}}
        mock_scanner.__getitem__.return_value = mock_host_result

        mock_port_scanner.return_value = mock_scanner

        # Executa o teste
        scanner = NmapScanner()
        open_ports = scanner.list_open_ports("192.168.1.1")

        # Verifica o resultado
        self.assertEqual(open_ports, [80])

    @patch('nmap.PortScanner')
    def test_get_service_info(self, mock_port_scanner):
        # Configura o mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]

        # Simula o objeto retornado por self.scanner[target]
        mock_host_result = MagicMock()
        mock_host_result.all_protocols.return_value = ["tcp"]
        mock_host_result.__getitem__.return_value = {80: {"state": "open", "name": "http", "product": "Apache"}}
        mock_scanner.__getitem__.return_value = mock_host_result

        mock_port_scanner.return_value = mock_scanner

        # Executa o teste
        scanner = NmapScanner()
        service_info = scanner.get_service_info("192.168.1.1", 80)

        # Verifica o resultado
        self.assertEqual(service_info["state"], "open")
        self.assertEqual(service_info["name"], "http")
        self.assertEqual(service_info["product"], "Apache")

    @patch('nmap.PortScanner')
    def test_list_open_ports_host_not_found(self, mock_port_scanner):
        # Configura o mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = []
        mock_port_scanner.return_value = mock_scanner

        # Executa o teste
        scanner = NmapScanner()
        with self.assertRaises(ValueError) as context:
            scanner.list_open_ports("192.168.1.1")

        # Verifica a mensagem de erro
        self.assertEqual(str(context.exception), "Host 192.168.1.1 não foi escaneado ou não foi encontrado.")

    @patch('nmap.PortScanner')
    def test_get_service_info_port_not_found(self, mock_port_scanner):
        # Configura o mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]

        # Simula o objeto retornado por self.scanner[target]
        mock_host_result = MagicMock()
        mock_host_result.all_protocols.return_value = ["tcp"]
        mock_host_result.__getitem__.return_value = {}
        mock_scanner.__getitem__.return_value = mock_host_result

        mock_port_scanner.return_value = mock_scanner

        # Executa o teste
        scanner = NmapScanner()
        with self.assertRaises(ValueError) as context:
            scanner.get_service_info("192.168.1.1", 80)

        # Verifica a mensagem de erro
        self.assertEqual(str(context.exception), "Porta 80 não encontrada no host 192.168.1.1.")