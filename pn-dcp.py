#/usr/bin/env python

import socket
import pndcp

ETH_P_ALL = 0x8892
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
rawSocket.bind(("vboxnet0", ETH_P_ALL))

pnclient = pndcp.PNDCP()

while True:
    packet = rawSocket.recvfrom(65565)
    response = pnclient.process_packet(packet[0])

    if response:
        print(response)
        rawSocket.send(response)
