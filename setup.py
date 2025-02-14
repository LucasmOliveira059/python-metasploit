from setuptools import setup, find_packages

setup(
    name="python-metasploit",
    version="0.1.0",
    description="Uma biblioteca Python para interagir com o Metasploit, Nmap e Wireshark.",
    author="Seu Nome",
    packages=find_packages(),
    install_requires=["pymetasploit3", "python-nmap", "pyshark", "googlesearch-python", "requests"],
    python_requires=">=3.6",
)