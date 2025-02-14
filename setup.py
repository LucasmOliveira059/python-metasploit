from setuptools import setup, find_packages

setup(
    name="python-metasploit",
    version="0.1.0",
    description="Uma biblioteca Python para interagir com o Metasploit, Nmap e Wireshark.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Lucasmoliveira059",
    author_email="lucasmoliveira059@gmail.com",
    url="https://github.com/LucasmOliveira059/python-metasploit/tree/master",
    packages=find_packages(),
    install_requires=["pymetasploit3",
                      "python-nmap",
                      "pyshark",
                      "googlesearch-python",
                      "requests", "dnspython"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache2.0",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
)