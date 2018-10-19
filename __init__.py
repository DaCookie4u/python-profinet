#/usr/bin/env python

import socket
import logging
import netifaces
import pndcp
# import dcerpc
import threading
import struct
import uuid
logging.basicConfig(level=logging.INFO)

PNIO_UUID = uuid.UUID('{dea00001-6c97-11d1-8271-00a02442df7d}')
OBJECT_UUID = uuid.UUID('{dea00000-6c97-11d1-8271-00640001ffff}')

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

        # Open UDP Socket for DCE/RPC requests
        logging.info('Listening for DCE/RPC request on ' + self._address + ':34964')
        self._dce_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dce_socket.bind((self._address, 34964))

        # Create a DCP instance
        self._dcp = pndcp.PnDcp(self._address, self._netmask, self._gateway)
        # self._dce = dcerpc.DceRpc()


    def start(self):
        threading.Thread(target = self._listen_pn).start()
        threading.Thread(target = self._listen_dcerpc).start()


    def _listen_pn(self):
        while True:
            (packet, address) = self._pn_socket.recvfrom(4096)
            logging.debug("incoming PN packet: " + " ".join(hex(c) for c in packet))

            dst = packet[0:6]
            src = packet[6:12]
            type = int.from_bytes(packet[12:14], byteorder='big')
            frameId = int.from_bytes(packet[14:16], byteorder='big')
            response = self._dispatch_pn_packet(frameId, packet[16:])

            if response:
                ethernet2 = src + bytes([int(byte, 16) for byte in self._mac.split(':')]) + b'\x81\x00'
                qHeader = b'\x00\x00' + b'\x88\x92'
                response = ethernet2 + qHeader + response
                logging.debug("outgoing packet: " + " ".join(hex(c) for c in response))
                self._pn_socket.send(response)


    def _listen_dcerpc(self):
        while True:
            (packet, address) = self._dce_socket.recvfrom(4096)

            # Packet should have at least the DCE/RPC header stuff
            if len(packet) < 80:
                continue

            # Lets assume its a DCE/RPC packet shall we
            logging.debug("incoming DCE packet: " + " ".join(hex(c) for c in packet))

            s = struct.Struct('BBBBBB')
            (version, type, flags1, flags2, boc, fp) = s.unpack(packet[0:6])
            byteorder = '<' if (boc >> 4 == 0x01) else '>'
            character = 'ebcdic' if (boc & 0x0f == 0x01) else 'ascii'

            s = struct.Struct(byteorder + '16s16s16s')
            (object_uuid, interface_uuid, activity_uuid) = s.unpack(packet[8:56])
            object_uuid = uuid.UUID(object_uuid.hex())
            interface_uuid = uuid.UUID(interface_uuid.hex())
            activity_uuid = uuid.UUID(activity_uuid.hex())

            s = struct.Struct(byteorder + 'HH')
            (fragment_len, fragmen_num) = s.unpack(packet[74:78])

            # We only work in PNIO interface and the fitting Object
            if (interface_uuid != PNIO_UUID):
                continue
            if (object_uuid != OBJECT_UUID):
                continue

            s = struct.Struct(byteorder + 'IH')
            (seqnum, opnum) = s.unpack(packet[64:70])

            if type == 0 and opnum == 0:
                response = (
                    version,
                    2,
                    10,
                    0,
                    0,
                    0,
                    0,
                    OBJECT_UUID.bytes,
                    PNIO_UUID.bytes,
                    activity_uuid.bytes,
                    0,
                    1,
                    seqnum,
                    opnum,
                    0xffff,
                    0xffff,
                    0,
                    0,
                    0,
                    0
                )
                s = struct.Struct('>BBBBHBB16s16s16sIIIHHHHHBB')
                self._dce_socket.sendto(s.pack(*response), address)


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

        if response:
            response = src + bytes(self._mac.split(':')) + b'\x81\x00\x00\x00' + b'\x88\x92' + response
            return response
        else:
            return 0


if __name__ == "__main__":
    server = Profinet("enp0s20f0u1u1")

    server.start()
