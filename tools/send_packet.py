#/usr/bin/env python

import socket


rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rawSocket.bind(("lo", 0))

dst = 0x010ecf000000
src = 0x286336865982
type = 0x8100
vid = 0x0000
vtype = 0x8892

ethernet2 = dst.to_bytes(6, byteorder='big') + src.to_bytes(6, byteorder='big') + type.to_bytes(2, byteorder='big')
vlantag = vid.to_bytes(2, byteorder='big') + vtype.to_bytes(2, byteorder='big')

payload = bytes.fromhex('fefe05000301000300800004ffff0000000000000000000000000000000000000000000000000000000000000000')

packet = ethernet2 + vlantag + payload

rawSocket.send(packet)
