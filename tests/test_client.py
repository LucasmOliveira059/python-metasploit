import unittest
from metasploit.client import MetasploitClient

class TestMetasploitClient(unittest.TestCase):
    def test_list_exploits(self):
        client = MetasploitClient('senha')
        exploits = client.list_exploits()
        self.assertIsInstance(exploits, list)

if __name__ == "__main__":
    unittest.main()