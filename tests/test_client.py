import socket
import unittest
from unittest.mock import MagicMock, patch
from metasploit.client import MetasploitClient


class TestClient(unittest.TestCase):

    def test_list_exploits(self):
        # Mock do MsfRpcClient
        mock_client = MagicMock()
        mock_client.modules.exploits = ["exploit1", "exploit2", "exploit3"]

        # Mock da instância de MetasploitClient
        with patch("metasploit.client.MsfRpcClient", return_value=mock_client):
            metasploit_client = MetasploitClient(password="senha")

            # Chama o método list_exploits
            exploits = metasploit_client.list_exploits()

            # Verifica se o resultado é o esperado
            self.assertEqual(exploits, ["exploit1", "exploit2", "exploit3"])

    def test_run_exploit_success(self):
        # Mock do MsfRpcClient e do módulo de exploit
        mock_client = MagicMock()
        mock_exploit = MagicMock()
        mock_exploit.execute.return_value = {"session_id": 123}

        mock_client.modules.use.return_value = mock_exploit

        # Mock da instância de MetasploitClient
        with patch("metasploit.client.MsfRpcClient", return_value=mock_client):
            metasploit_client = MetasploitClient(password="senha")

            # Configura as opções do exploit
            options = {"RHOSTS": "192.168.1.1", "RPORT": 445}

            # Chama o método run_exploit
            session_id = metasploit_client.run_exploit("windows/smb/ms17_010_eternalblue", options, confirm=False)

            # Verifica se o exploit foi executado e retornou um session_id
            self.assertEqual(session_id, 123)
            mock_exploit.execute.assert_called_once()

    def test_run_exploit_failure(self):
        # Mock do MsfRpcClient e do módulo de exploit
        mock_client = MagicMock()
        mock_exploit = MagicMock()
        mock_exploit.execute.return_value = None  # Simula falha na execução

        mock_client.modules.use.return_value = mock_exploit

        # Mock da instância de MetasploitClient
        with patch("metasploit.client.MsfRpcClient", return_value=mock_client):
            metasploit_client = MetasploitClient(password="senha")

            # Configura as opções do exploit
            options = {"RHOSTS": "192.168.1.1", "RPORT": 445}

            # Chama o método run_exploit
            session_id = metasploit_client.run_exploit("windows/smb/ms17_010_eternalblue", options, confirm=False)

            # Verifica se o exploit falhou e retornou None
            self.assertIsNone(session_id)
            mock_exploit.execute.assert_called_once()

    def test_resolver_dominio_success(self):
        # Mock da função socket.gethostbyname
        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            ip = MetasploitClient.resolver_dominio("example.com")
            self.assertEqual(ip, "192.168.1.1")

    def test_resolver_dominio_failure(self):
        # Mock da função socket.gethostbyname para simular erro
        with patch("socket.gethostbyname", side_effect=socket.error("Erro de resolução")):
            ip = MetasploitClient.resolver_dominio("invalid.domain")
            self.assertIsNone(ip)

    def test_configurar_payload(self):
        # Mock do MsfRpcClient e do módulo de payload
        mock_client = MagicMock()
        mock_payload = MagicMock()
        mock_payload.options = ["LHOST", "LPORT"]
        mock_payload.runoptions = {"LHOST": "192.168.1.1", "LPORT": 4444}

        mock_client.modules.use.return_value = mock_payload

        # Mock da função input para simular entradas do usuário
        with patch("builtins.input", side_effect=["192.168.1.1", "4444"]):
            # Mock da instância de MetasploitClient
            with patch("metasploit.client.MsfRpcClient", return_value=mock_client):

                options = MetasploitClient.configurar_payload(mock_client, "windows/meterpreter/reverse_tcp")

                # Verifica se as opções foram configuradas corretamente
                self.assertEqual(options, {})


if __name__ == "__main__":
    unittest.main()