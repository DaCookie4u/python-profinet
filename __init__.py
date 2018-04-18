#/usr/bin/env python

import socket
import pndcp

dcpServer = pndcp.PnDcp("lo")
dcpServer.start()

while dcpServer.is_alive():
    try:
        payload = 0
    except KeyboardInterrupt:
        dcpServer.stop()
        dcpServer.join()
