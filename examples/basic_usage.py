from metasploit import MetasploitClient

client = MetasploitClient('senha')
exploits = client.list_exploits()
print(exploits)