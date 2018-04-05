import socket

class PNDCP():
    typeOfStation = 'Raspberry Pi'
    nameOfStation = 'io-devicexb15b32'
    vendorId = 0x002a
    deviceId = 0x0314
    ipAddress = '192.168.0.6'
    ipNetmask = '255.255.255.0'
    ipGateway = '192.168.0.1'
    macAddress = bytes([0x00, 0xe0, 0x4c, 0x01, 0x13, 0x5b])
    macAddress = bytes([0x0a, 0x00, 0x27, 0x00, 0x00, 0x00])


    def __init__(self):
        return


    def block_device(self, suboption, data):
        block = bytes([2, suboption])
        block += (len(data) + 2).to_bytes(2, byteorder='big')
        block += bytes([0, 0])
        block += data
        # Add padding if necessary
        if len(data) % 2 > 0:
            block += bytes([0])
        return block


    def block_ip_ip(self):
        block = bytes([1, 2])
        block += bytes([0, 14, 0, 1]) # DCPBlockLength / BlockInfo IP set
        block += socket.inet_aton(self.ipAddress)
        block += socket.inet_aton(self.ipNetmask)
        block += socket.inet_aton(self.ipGateway)
        return block


    def identify_response(self, xid):
        res = bytes()
        # 2, 1: Device/Type Of Station
        res += self.block_device(1, bytes(self.typeOfStation, "utf-8"))
        # 2, 2: Device/Name Of Station
        res += self.block_device(2, bytes(self.nameOfStation, "utf-8"))
        # 2, 3: Device/Device ID
        res += self.block_device(3, self.vendorId.to_bytes(2, byteorder='big') + self.deviceId.to_bytes(2, byteorder='big'))
        # 2, 4: Device/Device Role
        res += self.block_device(4, bytes([0x01, 0x00]))
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
                if nameOfStation == self.nameOfStation:
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
        xId = payload[2:6]

        dataLength = int.from_bytes(payload[8:10], byteorder='big')

        if dataLength > 0:
            data = payload[10:10+dataLength]
        else:
            return 0

        # Get/Request
        if serviceId == 3 and serviceType == 0:
            # Iterate over all requested options
            i = 0
            options = []
            while i < len(data):
                options.append([data[i], data[i+1]])
                i += 2

            response = bytes()
            for option in options:
                if option[0] == 1 and option[1] == 2:
                    response += self.block_ip_ip()

            hdr = bytes([0xfe, 0xfd])                           # DCP identify response
            hdr += bytes([serviceId, 1])                        # ServiceID/ServiceType
            hdr += xId                                          # Xid
            hdr += bytes([0x00, 0x00])                          # Reserved
            hdr += len(response).to_bytes(2, byteorder='big')   # DCPDataLength
            response = hdr + response

        if response:
            return response
        else:
            return 0


    def process_packet(self, packet):
        response = 0
        dst = packet[0:6]
        src = packet[6:12]
        type = int.from_bytes(packet[12:14], byteorder='big')
        frameId = int.from_bytes(packet[14:16], byteorder='big')
        payload = packet[16:]

        # DCP identify request
        if frameId == 0xfefe:
            response = self.process_ident_req(payload)
        # DCP get/set
        elif frameId == 0xfefd:
            response = self.process_get_set_request(payload)

        if response:
            return src + self.macAddress + b'\x88\x92' + response
        else:
            return 0
