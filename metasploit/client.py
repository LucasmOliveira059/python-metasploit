from pymetasploit3.msfrpc import MsfRpcClient

class MetasploitClient:
    def __init__(self, password, port=55553):
        self.client = MsfRpcClient(password, port=port)

    def list_exploits(self):
        """Lista todos os exploits disponíveis."""
        return self.client.modules.exploits

    def run_exploit(self, exploit_name, target, payload):
        """Executa um exploit."""
        exploit = self.client.modules.use('exploit', exploit_name)
        exploit['RHOSTS'] = target
        exploit.execute(payload=payload)