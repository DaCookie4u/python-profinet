import socket
import logging
import struct

class PnDcp():
    _dcp_header = struct.Struct('>BBIHH')
    _block_header = struct.Struct('>BBH')
    _dcp_set_header = struct.Struct('>BBHH')

    _type_of_station = 'Python ProfiNET'
    _name_of_station = 'io-python'
    _vendor_id = 0xFFFF
    _device_id = 0x0001
    _device_role = 0x01


    def __init__(self, ip, sn, gw, name_of_station='io-python'):
        # Initialize locale variables
        self._ip_address = ip
        self._ip_netmask = sn
        self._ip_gateway = gw
        self._name_of_station = name_of_station


    def _create_block(self, option, suboption):
        # IP
        if option == 1:
            # IP/IP block
            if suboption == 2:
                s = struct.Struct('>H4s4s4s')
                data = s.pack(*(
                    1, # BlockInfo: IP set (1)
                    socket.inet_aton(self._ip_address),
                    socket.inet_aton(self._ip_netmask),
                    socket.inet_aton(self._ip_gateway)
                ))

        #  Device
        elif option == 2:
            # Device/Manufacturer specific block containing typeOfStation
            if suboption == 1:
                data = (0).to_bytes(2, byteorder='big') # BlockInfo: Reserved (0)
                data += self._type_of_station.encode("utf-8")

            # Device/Name of Station block
            elif suboption == 2:
                data = (0).to_bytes(2, byteorder='big') # BlockInfo: Reserved (0)
                data += self._name_of_station.encode("utf-8")

            # Device/Device ID block
            elif suboption == 3:
                s = struct.Struct('>HHH')
                data = s.pack(*(
                    0,  # BlockInfo: Reserved (0)
                    self._vendor_id,
                    self._device_id
                ))

            # Device/Device Role block
            elif suboption == 4:
                s = struct.Struct('>HBB')
                data = s.pack(*(
                    0, # BlockInfo: Reserved (0)
                    self._device_role,
                    0 # Reserved (0)
                ))

        length = len(data)
        s = struct.Struct('>BBH' + str(length) + 's' + ('x' if length % 2 else ''))
        block = (option, suboption, length, data)

        return s.pack(*block)


    # creates a Control/Response block for option, suboption with blockerror
    def _block_ctrl_response(self, option, suboption, blockerror):
        s = struct.Struct('>BBHBBBx')
        return s.pack(*(5, 4, 3, option, suboption, blockerror))


    def _identify_response(self):
        # 2, 1: Device/Type Of Station
        identify = self._create_block(2, 1)
        # 2, 2: Device/Name Of Station
        identify += self._create_block(2, 2)
        # 2, 3: Device/Device ID
        identify += self._create_block(2, 3)
        # 2, 4: Device/Device Role
        identify += self._create_block(2, 4)
        # 1, 2: IP/IP
        identify += self._create_block(1, 2)
        return identify


    def _process_ident_req(self, payload):
        response = 0

        (service_id, service_type, xid, response_delay, data_length) = self._dcp_header.unpack(payload[0:10])

        if data_length > 0:
            data = payload[10:10+data_length]
        else:
            return 0

        # Identify/Request
        if service_id == 5 and service_type == 0:
            (block_option, block_suboption, block_data_len) = self._block_header.unpack(data[0:4])

            # Block: All/All
            if block_option == 255 and block_suboption == 255:
                response = self._identify_response()
            # Block: Device/NameOfStation
            elif block_data_len > 0 and block_option == 2 and block_suboption == 2:
                name_of_station = data[4:4+block_data_len].decode("utf-8")
                if name_of_station == self._name_of_station:
                    response = self._identify_response()

        if response:
            hdr = (service_id, 1, xid, 0, len(response))
            return (0xfeff).to_bytes(2, byteorder='big') + self._dcp_header.pack(*hdr) + response
        else:
            return 0


    def _process_get_set_request(self, payload):
        response = 0

        (service_id, service_type, xid, response_delay, data_length) = self._dcp_header.unpack(payload[0:10])

        # TODO: we ignore responses for now
        if service_type == 0x01:
            return 0

        if data_length > 0:
            data = payload[10:10+data_length]
        else:
            return 0

        # Get/Request
        if service_id == 0x03 and service_type == 0x00:
            # Iterate over all requested options
            i = 0
            req_options = []
            while i < len(data):
                req_options.append([data[i], data[i+1]])
                i += 2

            response = bytes()
            for option in req_options:
                # Option: IP
                if option[0] == 0x01:
                    # Suboption: IP parameter
                    if option[1] == 0x02:
                        response += self._create_block(1, 2)
                    # Suboption: unsupported
                    else:
                        response += self._block_ctrl_response(option[0], option[1], 0x02)
                # Option: unsupported
                else:
                    response += self._block_ctrl_response(option[0], option[1], 0x01)

        # Set/Request
        elif service_id == 0x04 and service_type == 0x00:
            (block_option, block_suboption, block_data_len) = self._block_header.unpack(data[0:4])

            if block_data_len > 0:
                blockQualifier = int.from_bytes(data[4:6], byteorder='big')
                blockData = data[6:4+block_data_len]

            # Option: IP
            if block_option == 0x01:
                # We are unable to change any IP Suboptions
                response = self._block_ctrl_response(block_option, block_suboption, 0x03)
            # Option: Device
            elif block_option == 0x02:
                # Suboption: name_of_station
                if block_suboption == 0x02:
                    name_of_station = blockData.decode("utf-8")
                    self._name_of_station = name_of_station
                    if self._name_of_station == name_of_station:
                        response = self._block_ctrl_response(block_option, block_suboption, 0x00)
                    else:
                        response = self._block_ctrl_response(block_option, block_suboption, 0x03)
                # Suboption: unsupported
                else:
                    response = self._block_ctrl_response(block_option, block_suboption, 0x02)
            # Option: unsupported
            else:
                response = self._block_ctrl_response(block_option, block_suboption, 0x01)

        if response:
            hdr = (service_id, 1, xid, 0, len(response))
            return (0xfefd).to_bytes(2, byteorder='big') + self._dcp_header.pack(*hdr) + response
        else:
            return 0


    def process_packet(self, frameId, payload):
        # DCP hello
        if frameId == 0xfefc:
            logging.info('DCP: incoming hello (' + hex(frameId) + ')')
            response = 0 # TODO: we should probably work with this packet :)
        # DCP get/set
        elif frameId == 0xfefd:
            logging.info('DCP: incoming "get/set" (' + hex(frameId) + ')')
            response = self._process_get_set_request(payload)
        # DCP identify request
        elif frameId == 0xfefe:
            logging.info('DCP: incoming "identify multicast request" (' + hex(frameId) + ')')
            response = self._process_ident_req(payload)
        # DCP identify response
        elif frameId == 0xfeff:
            logging.info('DCP: incoming "identify response" (' + hex(frameId) + ')')
            response = 0 # TODO: we ignore responses for now

        if response:
            if len(response) < 42:
                response += bytes(42 - len(response))
            return response
        else:
            return 0
