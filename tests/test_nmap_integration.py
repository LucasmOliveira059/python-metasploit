import unittest
from unittest.mock import MagicMock, patch
from metasploit import NmapScanner  # Substitua pelo nome do seu módulo

class TestNmapScanner(unittest.TestCase):
    @patch('nmap.PortScanner')
    def test_scan_host(self, mock_port_scanner):
        # Configura o mock
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = None
        mock_scanner.__getitem__.return_value = {"tcp": {80: {"state": "open"}}}
        mock_port_scanner.return_value = mock_scanner

        # Executa o teste
        scanner = NmapScanner()
        result = scanner.scan_host("192.168.1.1")

        # Verifica o resultado
        self.assertIn("tcp", result)
        self.assertIn(80, result["tcp"])
        self.assertEqual(result["tcp"][80]["state"], "open")
        mock_scanner.scan.assert_called_once_with("192.168.1.1", arguments="-sV")

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