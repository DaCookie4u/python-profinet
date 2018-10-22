import socket
import logging

class PnIoDce():
    def __init__(self, ip):
        self._address = ip

        # Open UDP Socket for DCE/RPC requests
        logging.info('Listening for DCE/RPC request on ' + self._address + ':34964')
        self._dce_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dce_socket.bind((self._address, 34964))


    def listen(self):
        while True:
            (packet, address) = self._dce_socket.recvfrom(4096)

            # Packet should have at least the DCE/RPC header stuff
            if len(packet) < 80:
                continue

            # Lets assume its a DCE/RPC packet shall we
            logging.debug("incoming DCE packet: " + " ".join(hex(c) for c in packet))
