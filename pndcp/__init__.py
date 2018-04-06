import threading
import socket
import logging
logging.basicConfig(level=logging.DEBUG)

class PNDCP(threading.Thread):
    _typeOfStation = ''
    _nameOfStation = ''
    _vendorId = 0x0000
    _deviceId = 0x0000
    _deviceRole = 0x01
    _ipAddress = '192.168.0.6'
    _ipNetmask = '255.255.255.0'
    _ipGateway = '192.168.0.1'
    _macAddress = bytes([0x00, 0xe0, 0x4c, 0x01, 0x13, 0x5b])
    _macAddress = bytes([0x0a, 0x00, 0x27, 0x00, 0x00, 0x00])


    def __init__(self, interface, vendorId=0x504e, deviceId=0x5079, typeOfStation='Python ProfiNet', nameOfStation='io-py'):
        # Thread
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        # create socket
        self._dcpSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892))
        self._dcpSocket.bind((interface, 0x8892))

        # Initialize locale variables
        self._vendorId = vendorId
        self._deviceId = deviceId
        self._typeOfStation = typeOfStation
        self._nameOfStation = nameOfStation
        return


    def _stopped(self):
        return self._stop_event.is_set()


    def run(self):
        while not self._stopped():
            packet = self._dcpSocket.recvfrom(4096)
            print("request: " + " ".join(hex(c) for c in packet[0]))
            response = self.process_packet(packet[0])

            if response:
                print("response: " + " ".join(hex(c) for c in response))
                self._dcpSocket.send(response)


    def stop(self):
        self._stop_event.set()


    # Creates a DCP Block for option, suboption with data
    def dcp_block(self, option, suboption, data):
        block = bytes([option, suboption])   # Option: Device / Suboption: suboption
        block += len(data).to_bytes(2, byteorder='big')
        block += data
        # Add padding if necessary
        if len(data) % 2 > 0:
            block += bytes([0])
        return block


    # creates a Device/Manufacturer specific block containing typeOfStation
    def block_device_manuf(self):
        data = bytes([0x00, 0x00]) # BlockInfo: Reserved (0)
        data += bytes(self._typeOfStation, "utf-8")
        return self.dcp_block(0x02, 0x01, data)


    # creates a Device/Name of Station block
    def block_device_nameofstation(self):
        data = bytes([0x00, 0x00]) # BlockInfo: Reserved (0)
        data += bytes(self._nameOfStation, "utf-8")
        return self.dcp_block(0x02, 0x02, data)


    # creates a Device/Device ID block
    def block_device_dev_id(self):
        data = bytes([0x00, 0x00]) # BlockInfo: Reserved (0)
        data += self._vendorId.to_bytes(2, byteorder='big')
        data += self._deviceId.to_bytes(2, byteorder='big')
        return self.dcp_block(0x02, 0x03, data)


    # creates a Device/Device Role block
    def block_device_dev_role(self):
        data = bytes([0x00, 0x00]) # BlockInfo: Reserved (0)
        data += bytes([self._deviceRole])
        data += bytes([0x00]) # Reserved: 0
        return self.dcp_block(0x02, 0x04, data)


    # creates a Control/Response block for option, suboption with blockerror
    def block_ctrl_response(self, option, suboption, blockerror):
        data = bytes([option, suboption]) + bytes([blockerror])
        return self.dcp_block(0x05, 0x04, data)


    def block_ip_ip(self):
        block = bytes([0x01, 0x02])     # Option: IP / Suboption: IP
        block += (14).to_bytes(2, byteorder='big') # DCPBlockLength
        block += bytes([0x00, 0x01])    # BlockInfo: IP set
        block += socket.inet_aton(self._ipAddress)
        block += socket.inet_aton(self._ipNetmask)
        block += socket.inet_aton(self._ipGateway)
        return block


    def identify_response(self, xid):
        res = bytes()
        # 2, 1: Device/Type Of Station
        res += self.block_device_manuf()
        # 2, 2: Device/Name Of Station
        res += self.block_device_nameofstation()
        # 2, 3: Device/Device ID
        res += self.block_device_dev_id()
        # 2, 4: Device/Device Role
        res += self.block_device_dev_role()
        # 1, 2: IP/IP
        res += self.block_ip_ip()
        return res


    def process_ident_req(self, payload):
        response = 0
        serviceId = payload[0]
        serviceType = payload[1]
        xId = payload[2:6]

        responseDelay = int.from_bytes(payload[6:8], byteorder='big')
        dataLength = int.from_bytes(payload[8:10], byteorder='big')

        if dataLength > 0:
            data = payload[10:10+dataLength]
        else:
            return 0

        # Identify/Request
        if serviceId == 5 and serviceType == 0:
            blockOption = data[0]
            blockSuboption = data[1]

            blockDataLength = int.from_bytes(data[2:4], byteorder='big')

            # Block: All/All
            if blockOption == 255 and blockSuboption == 255:
                response = self.identify_response(xId)
            # Block: Device/NameOfStation
            elif blockDataLength > 0 and blockOption == 2 and blockSuboption == 2:
                nameOfStation = data[4:4+blockDataLength].decode("utf-8")
                if nameOfStation == self._nameOfStation:
                    response = self.identify_response(xId)

            if response:
                hdr = bytes([0xfe, 0xff])                           # DCP identify response
                hdr += bytes([serviceId, 1])                        # ServiceID/ServiceType
                hdr += xId                                          # Xid
                hdr += bytes([0x00, 0x00])                          # Reserved
                hdr += len(response).to_bytes(2, byteorder='big')   # DCPDataLength
                response = hdr + response

        if response:
            return response
        else:
            return 0


    def process_get_set_request(self, payload):
        response = 0
        serviceId = payload[0]
        serviceType = payload[1]
        if serviceType == 0x01: return 0 # TODO: we ignore responses for now
        xId = payload[2:6]

        dataLength = int.from_bytes(payload[8:10], byteorder='big')

        if dataLength > 0:
            data = payload[10:10+dataLength]
        else:
            return 0

        # Get/Request
        if serviceId == 0x03 and serviceType == 0x00:
            # Iterate over all requested options
            i = 0
            reqOptions = []
            while i < len(data):
                reqOptions.append([data[i], data[i+1]])
                i += 2

            response = bytes()
            for option in reqOptions:
                # Option: IP
                if option[0] == 0x01:
                    # Suboption: IP parameter
                    if option[1] == 0x02:
                        response += self.block_ip_ip()
                    # Suboption: unsupported
                    else:
                        response += self.block_ctrl_response(option[0], option[1], 0x02)
                # Option: unsupported
                else:
                    response += self.block_ctrl_response(option[0], option[1], 0x01)

        # Set/Request
        elif serviceId == 0x04 and serviceType == 0x00:
            blockOption = data[0]
            blockSuboption = data[1]

            blockDataLength = int.from_bytes(data[2:4], byteorder='big')

            if blockDataLength > 0:
                blockQualifier = int.from_bytes(data[4:6], byteorder='big')
                blockData = data[6:4+blockDataLength]


            # Option: IP
            if blockOption == 0x01:
                # We are unable to change any IP Suboptions
                response = self.block_ctrl_response(blockOption, blockSuboption, 0x05)
            # Option: Device
            elif blockOption == 0x02:
                # Suboption: NameOfStation
                if blockSuboption == 0x02:
                    nameOfStation = blockData.decode("utf-8")
                    self._nameOfStation = nameOfStation
                    if self._nameOfStation == nameOfStation:
                        response = self.block_ctrl_response(blockOption, blockSuboption, 0x00)
                    else:
                        response = self.block_ctrl_response(blockOption, blockSuboption, 0x03)
                # Suboption: unsupported
                else:
                    response = self.block_ctrl_response(blockOption, blockSuboption, 0x02)
            # Option: unsupported
            else:
                response = self.block_ctrl_response(blockOption, blockSuboption, 0x01)

        if response:
            hdr = bytes([0xfe, 0xfd])                           # DCP get/set
            hdr += bytes([serviceId, 0x01])                     # ServiceID/ServiceType
            hdr += xId                                          # Xid
            hdr += bytes([0x00, 0x00])                          # Reserved
            hdr += len(response).to_bytes(2, byteorder='big')   # DCPDataLength
            return hdr + response
        else:
            return 0


    def process_packet(self, packet):
        response = 0
        dst = packet[0:6]
        src = packet[6:12]
        type = int.from_bytes(packet[12:14], byteorder='big')

        frameId = int.from_bytes(packet[14:16], byteorder='big')
        payload = packet[16:]

        # DCP hello
        if frameId == 0xfefc:
            logging.info('DCP: incoming hello (' + hex(frameId) + ')')
            response = 0 # TODO: we should probably work with this packet :)
        # DCP get/set
        elif frameId == 0xfefd:
            logging.info('DCP: incoming "get/set" (' + hex(frameId) + ')')
            response = self.process_get_set_request(payload)
        # DCP identify request
        elif frameId == 0xfefe:
            logging.info('DCP: incoming "identify multicast request" (' + hex(frameId) + ')')
            response = self.process_ident_req(payload)
        # DCP identify response
        elif frameId == 0xfeff:
            logging.info('DCP: incoming "identify response" (' + hex(frameId) + ')')
            response = 0 # TODO: we ignore responses for now

        if response:
            if len(response) < 42:
                response += bytes(42 - len(response))
            return src + self._macAddress + b'\x81\x00\x00\x00' + b'\x88\x92' + response
        else:
            return 0
