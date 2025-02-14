import unittest
from unittest.mock import patch, MagicMock
from metasploit import WebVulnerabilityScanner

class TestWebVulnerabilityScanner(unittest.TestCase):
    @patch('googlesearch.search')
    def test_google_dork_search(self, mock_search):
        # Configura o mock
        mock_search.return_value = [
            "http://example.com/page1",
            "http://example.com/page2"
        ]

        # Executa o teste
        scanner = webvulnerabilityscanner()
        results = scanner.google_dork_search("inurl:index.php?id=", num_results=2)

        # Verifica o resultado
        self.assertEqual(len(results), 2)
        self.assertIn("http://example.com/page1", results)
        self.assertIn("http://example.com/page2", results)
        mock_search.assert_called_once_with("inurl:index.php?id=", num=2, stop=2, pause=2)

    @patch('requests.get')
    def test_check_sql_injection(self, mock_get):
        # Configura o mock
        mock_response = MagicMock()
        mock_response.text = "Error: SQL syntax"
        mock_get.return_value = mock_response

        # Executa o teste
        scanner = webvulnerabilityscanner()
        is_vulnerable = scanner.check_sql_injection("http://example.com/page?id=1")

        # Verifica o resultado
        self.assertTrue(is_vulnerable)
        mock_get.assert_called_once_with(
            "http://example.com/page?id=' OR '1'='1",
            headers={"User-Agent": "Mozilla/5.0"}
        )

    @patch('web_vulnerability_scanner.WebVulnerabilityScanner.check_sql_injection')
    @patch('web_vulnerability_scanner.WebVulnerabilityScanner.google_dork_search')
    def test_scan_with_dorks(self, mock_dork_search, mock_check_sql):
        # Configura os mocks
        mock_dork_search.return_value = [
            "http://example.com/page1",
            "http://example.com/page2"
        ]
        mock_check_sql.side_effect = [True, False]  # Simula resultados de SQL Injection

        # Executa o teste
        scanner = webvulnerabilityscanner()
        vulnerable_urls = scanner.scan_with_dorks("inurl:index.php?id=", num_results=2)

        # Verifica o resultado
        self.assertEqual(len(vulnerable_urls), 1)
        self.assertIn("http://example.com/page1", vulnerable_urls)
        mock_dork_search.assert_called_once_with("inurl:index.php?id=", num_results=2)
        mock_check_sql.assert_any_call("http://example.com/page1")
        mock_check_sql.assert_any_call("http://example.com/page2")

    @patch('googlesearch.search')
    def test_google_dork_search_error(self, mock_search):
        # Configura o mock para simular uma exceção
        mock_search.side_effect = Exception("Erro de pesquisa")

        # Executa o teste
        scanner = webvulnerabilityscanner()
        results = scanner.google_dork_search("inurl:index.php?id=", num_results=2)

        # Verifica o resultado
        self.assertEqual(len(results), 0)