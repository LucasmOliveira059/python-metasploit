import pyshark

class WiresharkCapture:
    def __init__(self, interface):
        self.interface = interface

    def start_capture(self, filter_expression=None):
        """Inicia a captura de pacotes."""
        return pyshark.LiveCapture(interface=self.interface, display_filter=filter_expression)