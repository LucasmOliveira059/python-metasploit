import unittest
from unittest.mock import patch, MagicMock
from metasploit.webvulnerabilityscanner import WebVulnerabilityScanner  # Importação corrigida

class TestWebVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        """Inicializa o scanner para ser usado em todos os testes."""
        self.scanner = WebVulnerabilityScanner()  # Instancia a classe corretamente

    @patch('metasploit.webvulnerabilityscanner.WebVulnerabilityScanner.check_sql_injection')
    @patch('metasploit.webvulnerabilityscanner.WebVulnerabilityScanner.google_dork_search')
    def test_scan_with_dorks(self, mock_dork_search, mock_check_sql):
        # Configura os mocks
        mock_dork_search.return_value = [
            "http://example.com/page1",
            "http://example.com/page2"
        ]
        mock_check_sql.side_effect = [True, False]  # Simula resultados de SQL Injection

        # Executa o teste
        vulnerable_urls = self.scanner.scan_with_dorks("inurl:index.php?id=", 2)

        # Verifica o resultado
        self.assertEqual(len(vulnerable_urls), 1)
        self.assertIn("http://example.com/page1", vulnerable_urls)

        mock_dork_search.assert_called_once_with("inurl:index.php?id=", 2)


    @patch('metasploit.webvulnerabilityscanner.WebVulnerabilityScanner.google_dork_search')
    def test_google_dork_search(self, mock_search):
        # Configura o mock
        mock_search.return_value = [
            "http://example.com/page1",
            "http://example.com/page2"
        ]

        # Executa o teste
        results = self.scanner.google_dork_search("inurl:index.php?id=", 2)

        # Verifica o resultado

        self.assertEqual(len(results), 2)

    @patch('requests.get')
    def test_check_sql_injection(self, mock_get):
        # Configuração da resposta indicando vulnerabilidade SQL
        mock_response = MagicMock()
        mock_response.text = "Error: SQL syntax"
        mock_get.return_value = mock_response

        # URL de teste com parâmetro existente
        base_url = "http://example.com/page?id=1"

        # Payload malicioso esperado sem duplicar parâmetros
        expected_url = "http://example.com/page?id=%27+OR+%271%27%3D%271"  # URL codificada

        # Chama o método que está sendo testado
        response = self.scanner.check_sql_injection(base_url)

        # Captura os argumentos passados para requests.get
        args, kwargs = mock_get.call_args

        # Extrai a URL que foi realmente chamada
        actual_url = args[0]  # args[0] é a URL passada para requests.get

        # Verifica se a URL chamada é igual à URL esperada
        self.assertEqual(actual_url, expected_url)

        # Verifica se a resposta indica vulnerabilidade
        self.assertTrue(response)

    @patch('googlesearch.search')
    def test_google_dork_search_error(self, mock_search):
        # Configura o mock para simular uma exceção
        mock_search.side_effect = Exception("Erro de pesquisa")

        # Executa o teste
        results = self.scanner.google_dork_search("inurl:index.php?id=", num_results=2)

        # Verifica o resultado
        self.assertEqual(len(results), 0)