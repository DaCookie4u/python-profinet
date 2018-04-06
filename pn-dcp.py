#/usr/bin/env python

import socket
import pndcp

dcpServer = pndcp.PNDCP("vboxnet0")
dcpServer.start()

while dcpServer.is_alive():
    try:
        payload = 0
    except KeyboardInterrupt:
        dcpServer.stop()
