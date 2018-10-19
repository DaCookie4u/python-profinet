#/usr/bin/env python

import socket
import logging
import netifaces
import dcp

class Profinet():
    def __init__(self, interface):
        self._pnSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892))
        self._pnSocket.bind((interface, 0x8892))

        self._ipAddress = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        self._ipNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
        if len(netifaces.gateways()['default']) > 0 and netifaces.gateways()['default'][netifaces.AF_INET]:
            self._ipGateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        else:
            self._ipGateway = self._ipAddress
        self._macAddress = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
        self._dcpService = dcp.Dcp(self._ipAddress, self._ipNetmask, self._ipGateway)


    def listen(self):
        (packet, address) = self._pnSocket.recvfrom(4096)
        logging.debug("incoming packet: " + " ".join(hex(c) for c in packet))

        dst = packet[0:6]
        src = packet[6:12]
        type = int.from_bytes(packet[12:14], byteorder='big')
        frameId = int.from_bytes(packet[14:16], byteorder='big')
        response = self._dispatch_packet(frameId, packet[16:])

        if response:
            ethernet2 = src + bytes([int(byte, 16) for byte in self._macAddress.split(':')]) + b'\x81\x00'
            qHeader = b'\x00\x00' + b'\x88\x92'
            response = ethernet2 + qHeader + response
            logging.debug("outgoing packet: " + " ".join(hex(c) for c in response))
            self._pnSocket.send(response)


    def _dispatch_packet(self, frameId, payload):
        # DCP hello
        if frameId >= 0xfefc and frameId <= 0xfeff:
            logging.debug('Dispatching packet to DCP')
            return self._dcpService.process_packet(frameId, payload)
        else:
            logging.info('Received unknown FrameID: ' + hex(frameId))
            return 0

        if response:
            response = src + bytes(self._macAddress.split(':')) + b'\x81\x00\x00\x00' + b'\x88\x92' + response
            return response
        else:
            return 0

if __name__ == "__main__":
    server = Profinet("enp0s20f0u1u1")

    while True:
        try:
            server.listen()
        except KeyboardInterrupt:
            break
