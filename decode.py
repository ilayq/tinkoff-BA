import sys

import base64
from dataclasses import dataclass
from typing import List

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import urllib.request

################################################################### ULEB128 ENCODING/DECODING AND crc8 ########################################################################################################################


def split_bytes_by_chunks(data: bytes):
    cur = [data[0]]
    for idx in range(1, len(data)):
        if data[idx] > data[idx - 1] and data[idx - 1] < 128:
            yield bytearray(cur)
            cur = [data[idx]]
        else:
            cur.append(data[idx])
    if cur:
        yield bytearray(cur)


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x11d
            else:
                crc <<= 1
    return crc


def decodeULEB128(byte_arr: bytes) -> int:
    value = 0
    shift = 0
    for byte in byte_arr:
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return value 


def encodeULEB128(num: int) -> bytearray:
    result = bytearray()
    
    while True:
        byte = num & 0x7F
        num >>= 7
        
        if num != 0:
            byte |= 0x80
            
        result.append(byte)
        
        if num == 0:
            break
    return result #if decodeULEB128(result[:len(result) - 1]) != decodeULEB128(result) else result[:len(result) - 1]


##################################################################### DataClasses ######################################################################################################################

############ Base classes ##################


class cmd_body_class:
    pass


@dataclass
class Payload:
    src: int 
    dst: int 
    serial: int 
    dev_type: int 
    cmd: int
    cmd_body: cmd_body_class

    def __bytes__(self):
        arr = bytes(encodeULEB128(self.src) + encodeULEB128(self.dst) + encodeULEB128(self.serial) + encodeULEB128(self.dev_type) + encodeULEB128(self.cmd))
        if self.cmd_body:
            arr += bytes(self.cmd_body)
        return arr if arr else b''


@dataclass
class Packet:
    length: int
    payload: Payload
    crc: int


    def __bytes__(self):
        return bytes([self.length]) + bytes(self.payload) + bytes([crc8(bytes(self.payload))])


@dataclass
class dev_props_class:
    pass


class device_class:
    dev_name: str
    dev_prop = None


################# Implementation #####################


@dataclass
class timer_cmd_6_body(cmd_body_class):
    timestamp: int

    def __bytes__(self):
        return bytes(encodeULEB128(self.timestamp))



@dataclass
class timer_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props = None

    def __bytes__(self):
        return bytes([len(self.dev_name)]) + self.dev_name.encode()
 


@dataclass
class smart_hub_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props = None

    def __bytes__(self):
        return bytes([len(self.dev_name)]) + self.dev_name.encode()


@dataclass
class lamp_and_socket_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props = None

    def __bytes__(self):
        return bytes([len(self.dev_name)]) + self.dev_name.encode()


@dataclass
class lamp_and_socket_cmd_4_body(cmd_body_class):
    is_enabled: bool

    def __bytes__(self):
        return bytes([self.is_enabled])


@dataclass
class lamp_and_socket_cmd_5_body(cmd_body_class):
    command: bool

    def __bytes__(self):
        return bytes([self.command])


@dataclass
class env_sensor_operation(cmd_body_class):
    op: int
    value: int
    name: str

    def __bytes__(self):
       return bytes(encodeULEB128(self.op) + encodeULEB128(self.value) + encodeULEB128(len(self.name)) + self.name.encode())



@dataclass
class env_sensor_props(cmd_body_class):
    sensors: int
    triggers: List[env_sensor_operation]

    def __bytes__(self):
        triggers_bytes = bytearray()
        for tr in self.triggers:
            triggers_bytes.extend(bytes(tr))
        return bytes(encodeULEB128(self.sensors) + encodeULEB128(len(self.triggers)) + triggers_bytes)


@dataclass
class env_sensor_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props: env_sensor_props

    def __bytes__(self):
        return bytes([len(self.dev_name)]) + self.dev_name.encode() + bytes(self.dev_props)


@dataclass
class env_sensor_cmd_4_body(cmd_body_class):
    values: List[int]

    def __bytes__(self):
        s = bytearray([len(self.values)])
        for value in self.values:
            s += encodeULEB128(value)
        return bytes(s)


@dataclass
class switch_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props: List[str]

    def __bytes__(self):
        ans = bytearray([len(self.dev_name)])
        ans += self.dev_name.encode()
        ans += bytes([len(self.dev_props)])
        for string in self.dev_props:
            ans += bytes([len(string)]) + string.encode()
        return bytes(ans)


@dataclass
class switch_cmd_4_body(cmd_body_class):
    is_enabled: bool

    def __bytes__(self):
        return bytes([self.is_enabled])


class WrongCMDError(BaseException):
    pass


class WrongCRC8(BaseException):
    pass


################################################################################ MAIN PART OF DECODING #############################################################################################################################################


def read_triggers(data: bytes, l):
    
    operations = []
    values = []
    names = []
    while len(operations) < l:
        pos = 0
        operations.append(data[pos])
        pos += 1
        value = bytearray([data[pos]])
        while data[pos + 1] < data[pos] and data[pos] > 127:
            value.extend(bytearray([data[pos + 1]]))
            pos += 1
        values.append(decodeULEB128(value))
        pos += 1

        name_len = data[pos]
        pos += 1
        name = data[pos : name_len + pos]
        data = data[name_len + pos:]
        names.append(name.decode())

    yield from zip(operations, values, names)


def parse_words_from_bytes(data: bytes):
    cur = ''
    for byte in data:
        if 32 <= byte <= 126:
            cur += chr(byte)
        else:
            if cur:
                yield cur
            cur = ''
    if cur:
        yield cur


def decode_cmd_body(dev_type: int, cmd: int, cmd_body_bytes: bytes) -> cmd_body_class:
    match (dev_type, cmd):
        case (1, 1) | (1, 2):
            return smart_hub_cmd_1_2_body(dev_name=cmd_body_bytes[1:].decode('utf-8'))
        case (1, 3) | (1, 4) | (1, 5) | (1, 6):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')
        case (2, 1) | (2, 2):
            decoded_string = cmd_body_bytes
            name_len = decoded_string[0]
            dev_name = decoded_string[1:name_len + 1].decode()
            pos = name_len + 1
            sensors = decoded_string[pos]
            pos += 1
            triggers_len = decoded_string[pos]
            triggers = decoded_string[pos + 1:]
            triggers = [env_sensor_operation(*trigger) for trigger in read_triggers(triggers, triggers_len)]
            return env_sensor_cmd_1_2_body(dev_name=dev_name,
                                           dev_props=env_sensor_props(sensors=sensors, 
                                                            triggers=triggers))
        case (2, 3):
            return None

        case (2, 4):
            nums = list(split_bytes_by_chunks(cmd_body_bytes[1:]))
            for idx in range(len(nums)):
                nums[idx] = decodeULEB128(nums[idx])
            return env_sensor_cmd_4_body(nums)
        case (2, 5) | (2, 6):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}') 
        case (3, 1) | (3, 2):
            words = list(parse_words_from_bytes(cmd_body_bytes))
            return switch_cmd_1_2_body(dev_name=words[0], dev_props=words[1:len(words)])
        case (3, 3):
            return None
        case (3, 4):
            return switch_cmd_4_body(is_enabled=cmd_body_bytes[0])
        case (4, 1) | (4, 2) | (5, 1) | (5, 2):
            return lamp_and_socket_cmd_1_2_body(dev_name=cmd_body_bytes[1:].decode('utf8'))
        case (4, 3) | (5, 3):
            return None
        case (4, 4) | (5, 4):
            return lamp_and_socket_cmd_4_body(is_enabled=cmd_body_bytes[0])
        case (4, 5) | (5, 5):
            return lamp_and_socket_cmd_5_body(command=cmd_body_bytes[0])
        case (6, 1):
            return timer_cmd_1_2_body(dev_name=cmd_body_bytes[1:].decode('utf8'))
        case (6, 6):
            return timer_cmd_6_body(timestamp=decodeULEB128(cmd_body_bytes))
        case (6, 2):
            return timer_cmd_1_2_body(dev_name=cmd_body_bytes[1:].decode('utf8'))
        case _:
            raise NotImplementedError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')


def decode_packets(string):
    dcdstr = ''
    try:
        dcdstr = base64.urlsafe_b64decode(string + '==')
    except Exception as e:
        raise e
    # print(dcdstr)
    shift = 0
    while shift < len(dcdstr):
        length = dcdstr[0 + shift]
        payload = dcdstr[1 + shift:length + shift + 1]
        crc = dcdstr[length + 1 + shift]
        pointer = 0
        src = payload[0]

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            src = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        dst = payload[pointer]

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            dst = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1


        serial = payload[pointer]
        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            serial = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1 

        dev_type = payload[pointer]
        cmd = payload[pointer + 1]

        # print(length, src, dst, serial, dev_type, cmd)


        cmd_body_bytes = payload[pointer + 2 : length + 1]
        # print(cmd_body_bytes)
        p = Payload(
                src=(src),
                dst=(dst),
                serial=serial,
                dev_type=dev_type,
                cmd=cmd,
                cmd_body=decode_cmd_body(dev_type, cmd, cmd_body_bytes)
                )
        shift += length + 2

        yield Packet(length=length,
                     payload=p,
                     crc=crc)
        

################################################################################################# ENCODING #############################################################################################################################


def encode_message_to_base64(msg: List) -> str:
    result = bytearray()
    for element in msg:
        if isinstance(element, int):
            # print(element, encodeULEB128(element))
            if element < 256:
                result.extend(bytearray([element]))
            else:
                result.extend(encodeULEB128(element))
        elif isinstance(element, str):
            result.extend(element.encode())
        else:
            try:
                result.extend(encode_message_to_base64(element))
            except ValueError:
                continue
    
    return base64.urlsafe_b64encode(result).decode('utf8')
        

################################################################################################# SERVER PART #############################################################################################################################

# TODO 
class Server(BaseHTTPRequestHandler):
    def __init__(self, url, address):
        self.url = url
        self.address = address
        self.templates = {}
        self.serial = 1
        self.name = "myhub"
        self.__make_cmd_1_template()

    def __send_initial_request(self, msg: bytes):
        request = urllib.request.Request(url=self.url, method="POST", data=msg)
        s = urllib.request.urlopen(request).read().decode()
        print(s)
        [print(pack) for pack in decode_packets(s)]

    def __make_cmd_1_template(self):
        # payload = {
        #     "src":  self.address,
        #     "dst": 16383,
        #     "serial": self.serial,
        #     "dev_type": 1,
        #     "cmd": 1,
        #     "cmd_body": {
        #         "dev_name": self.name
        #     }
        # }
        payload = Payload(
            src=self.address,
            dst=16383,
            serial=self.serial,
            dev_type=1,
            cmd=1,
            cmd_body=smart_hub_cmd_1_2_body(
                dev_name=self.name
            )
        )
        packet = Packet(
            length=len(bytes(payload)),
            payload=payload,
            crc=crc8(bytes(payload))
        )
        self.__send_initial_request(base64.urlsafe_b64encode(bytes(packet)))
    

if __name__ == '__main__':


    url, address = sys.argv[1], int(sys.argv[2], 16)
    server = Server(url, address)

    ################################ TESTS ########################################################################################
    # tests = []
    # tests.append("DAH_fwEBAQVIVUIwMeE")
    # tests.append("DAH_fwIBAgVIVUIwMak")    
    # tests.append("OAL_fwMCAQhTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI03Q")
    # tests.append("OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w")
    # tests.append("BQECBQIDew")
    # tests.append("EQIBBgIEBKUB2jbUjgaMjfILoQ")
    # tests.append("IgP_fwcDAQhTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDO1")
    # tests.append("IgP_fwgDAghTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDMo")
    # tests.append("BQEDCQMDoA")
    # tests.append("BgMBCgMEAac")
    # tests.append("DQT_fwsEAQZMQU1QMDG8")
    # tests.append("DQT_fwwEAgZMQU1QMDGU")
    # tests.append("BQEEDQQDqw")
    # tests.append("BgQBDgQEAaw")
    # tests.append("BgEEDwQFAeE")
    # tests.append("DwX_fxAFAQhTT0NLRVQwMQ4")
    # tests.append("DwX_fxEFAghTT0NLRVQwMc0")
    # tests.append("BQEFEgUD5A")
    # tests.append("BgUBEwUEAQ8")
    # tests.append("BgEFFAUFAQc")
    # tests.append("Dgb_fxUGAQdDTE9DSzAxHA")
    # tests.append("DAb_fxgGBpabldu2NNM")


    # for test in tests:
    #     for packet in decode_packets(test):
    #         assert bytes(packet) == base64.urlsafe_b64decode(test + '==='), (bytes(packet), base64.urlsafe_b64decode(test + '==='))
