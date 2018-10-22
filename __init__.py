#/usr/bin/env python

import socket
import logging
import netifaces
import pndcp
import pniodce
import threading
import struct
import uuid
logging.basicConfig(level=logging.INFO)

IFACE_UUID_PNIO_DEV = uuid.UUID('{dea00001-6c97-11d1-8271-00a02442df7d}')
IFACE_UUID_PNIO_CTRL = uuid.UUID('{dea00002-6c97-11d1-8271-00a02442df7d}')
OBJECT_UUID_PYTHON_IO = uuid.UUID('{dea00000-6c97-11d1-8271-00640001ffff}')

class Profinet():
    def __init__(self, interface):

        # Get information about the given interface
        self._address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        self._netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
        if len(netifaces.gateways()['default']) > 0 and netifaces.gateways()['default'][netifaces.AF_INET]:
            self._gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        else:
            self._gateway = self._address
        self._mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

        # Listen for ProfiNET packets
        logging.info('Listening for PROFINET packets on ' + interface)
        self._pn_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892))
        self._pn_socket.bind((interface, 0x8892))

        # Create a DCP instance
        self._dcp = pndcp.PnDcp(self._address, self._netmask, self._gateway)
        self._pniodce = pniodce.PnIoDce(self._address)


    def start(self):
        threading.Thread(target = self._listen_pn).start()
        threading.Thread(target = self._pniodce.listen).start()


    def _listen_pn(self):
        while True:
            (packet, address) = self._pn_socket.recvfrom(4096)
            logging.debug("incoming PN packet: " + " ".join(hex(c) for c in packet))

            s = struct.Struct('>6s6sHH')
            (dst, src, type, frameId) = s.unpack(packet[0:16])
            response = self._dispatch_pn_packet(frameId, packet[16:])

            if response:
                s = struct.Struct('>6s6sHHH')
                header = (
                    src, bytes([int(byte, 16) for byte in self._mac.split(':')]), # dst and src mac
                    0x8100, 0x0000, # 802.1q tag, prio 0
                    0x8892 # Type: PROFINET
                )
                response = s.pack(*header) + response
                logging.debug("outgoing packet: " + " ".join(hex(c) for c in response))
                self._pn_socket.send(response)


    def _dispatch_pn_packet(self, frameId, payload):
        # DCP hello
        if frameId >= 0xfefc and frameId <= 0xfeff:
            logging.debug('Dispatching packet to DCP')
            return self._dcp.process_packet(frameId, payload)
        elif frameId >= 0x8000 and frameId <= 0xBBFF:
            loggin.debug('Dispatching packet to PNIO')
            return 0
        else:
            logging.info('Received unknown FrameID: ' + hex(frameId))
            return 0


if __name__ == "__main__":
    server = Profinet("enp0s20f0u1u1")

    server.start()
