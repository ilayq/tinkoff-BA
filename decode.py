import sys

import base64
from dataclasses import dataclass
from typing import List, Iterable

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import urllib.request

################################################################### ULEB128 ENCODING/DECODING AND crc8 ########################################################################################################################


def split_bytes_by_chunks(data: bytes):
    cur = [data[0]]
    for idx in range(1, len(data)):
        if data[idx] > data[idx - 1]:
            yield bytearray(cur)
            cur = [data[idx]]
        else:
            cur.append(data[idx])
    if cur:
        yield cur


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


def encodeULEB128(val: int) -> bytearray:
    if not val:
        return [0]
    buf = []
    i = 0
    while val != 0:
        b = val & 0x7f
        val >>= 7
        if val != 0:
            b |= 0x80
        buf.append(b)
        i += 1
    return bytearray(buf)


##################################################################### DataClasses ######################################################################################################################

############ Base classes ##################

@dataclass
class Payload:
    src: int 
    dst: int 
    serial: int 
    dev_type: int 
    cmd: int
    cmd_body: bytes


@dataclass
class Packet:
    length: int
    payload: Payload
    crc8: int


class cmd_body_class:
    pass


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



@dataclass
class timer_cmd_1_2_body:
    dev_name: str
    dev_props = None 
 


@dataclass
class smart_hub_cmd_1_2_body:
    dev_name: str
    dev_props = None


@dataclass
class lamp_and_socket_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props = None


@dataclass
class lamp_and_socket_cmd_4_body(cmd_body_class):
    is_enabled: bool 


@dataclass
class lamp_and_socket_cmd_5_body(cmd_body_class):
    command: bool


@dataclass
class env_sensor_operation:
    op: int
    value: int
    name: str


@dataclass
class env_sensor_props:
    sensors: int
    triggers: List[env_sensor_operation]


@dataclass
class env_sensor_cmd_1_2_body:
    dev_name: str
    dev_props: env_sensor_props


@dataclass
class env_sensor_cmd_4_body(cmd_body_class):
    values: List[int]


@dataclass
class switch_cmd_1_2_body(cmd_body_class):
    dev_name: str
    dev_props: List[str]


@dataclass
class switch_cmd_4_body(cmd_body_class):
    is_enabled: bool


class WrongCMDError(BaseException):
    pass


class WrongCRC8(BaseException):
    pass


################################################################################ MAIN PART OF DECODING #############################################################################################################################################


def read_triggers(data: bytes):
    pos = 0
    operations = []
    values = []
    names = []
    while pos < len(data):
        operations.append(data[pos])
        pos += 1
        value = data[pos]
        if data[pos + 1] > data[pos]:
            value = decodeULEB128(data[pos : pos + 2])
            pos += 1
        values.append(value)
        pos += 1
        name = ''
        while pos < len(data):
            if data[pos] not in range(32, 127):
                break
            else:
                name += chr(data[pos])
                pos += 1
        names.append(name)

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
            return smart_hub_cmd_1_2_body(dev_name=cmd_body_bytes.decode('utf-8'))
        case (1, 3) | (1, 4) | (1, 5) | (1, 6):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')
        case (2, 1) | (2, 2):
            decoded_string = cmd_body_bytes
            dev_name = ''
            pos = 0
            for i in range(len(decoded_string)):
                byte = decoded_string[i]
                if 31 < byte < 127:
                    dev_name += chr(byte)
                else:
                    pos = i
                    break
            sensors = decoded_string[pos]
            triggers = cmd_body_bytes[pos + 1:]
            triggers = [env_sensor_operation(*trigger) for trigger in read_triggers(triggers)]
            return env_sensor_cmd_1_2_body(dev_name=dev_name,
                                           dev_props=env_sensor_props(sensors=sensors, 
                                                            triggers=triggers))
        case (2, 3):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')

        case (2, 4):
            nums = list(split_bytes_by_chunks(cmd_body_bytes))
            for idx in range(len(nums)):
                nums[idx] = decodeULEB128(nums[idx])
            return env_sensor_cmd_4_body(nums)
        case (2, 5) | (2, 6):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}') 
        case (3, 1) | (3, 2):
            words = list(parse_words_from_bytes(cmd_body_bytes))
            return switch_cmd_1_2_body(dev_name=words[0], dev_props=words[1:len(words)])
        case (3, 3):
            raise WrongCMDError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')
        case (3, 4):
            return switch_cmd_4_body(is_enabled=cmd_body_bytes[0])
        case (4, 1) | (4, 2) | (5, 1) | (5, 2):
            return lamp_and_socket_cmd_1_2_body(dev_name=cmd_body_bytes.decode('utf8'))
        case (4, 4) | (5, 4):
            return lamp_and_socket_cmd_4_body(is_enabled=cmd_body_bytes[0])
        case (4, 5) | (5, 5):
            return lamp_and_socket_cmd_5_body(command=cmd_body_bytes[0])
        case (6, 6):
            return timer_cmd_6_body(timestamp=decodeULEB128(cmd_body_bytes))
        case (6, 2):
            return timer_cmd_1_2_body(dev_name=cmd_body_bytes.decode('utf8'))
        case _:
            raise NotImplementedError(f'dev_type: {dev_type}\ncmd: {cmd}\nbytes: {cmd_body_bytes}')


def decode_packets(string):
    dcdstr = ''
    try:
        dcdstr = base64.urlsafe_b64decode(string + '==')
    except Exception as e:
        raise e

    shift = 0
    while shift < len(dcdstr):
        length = dcdstr[0 + shift]
        payload = dcdstr[1 + shift:length + shift + 1]
        crc = dcdstr[length + 1 + shift]
        pointer = 0
        src = payload[0]

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer]:
            src = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        dst = payload[pointer]

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer]:
            dst = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        serial = payload[pointer]

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer]:
            serial = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1 

        dev_type = payload[pointer]
        cmd = payload[pointer + 1]


        cmd_body_bytes = payload[pointer + 3 : length + 1]

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
                     crc8=crc)
        

################################################################################################# ENCODING #############################################################################################################################


def encode_message_to_base64(msg: List) -> str:
    result = bytearray()
    for element in msg:
        if isinstance(element, int):
            result.append(encodeULEB128(element))
        elif isinstance(element, str):
            result.append(element.encode())
        else:
            try:
                result.append(encode_message_to_base64(element))
            except ValueError:
                continue

    return base64.urlsafe_b64encode(result).decode()
        

################################################################################################# SERVER PART #############################################################################################################################


class Server:
    def __init__(self, url, address):
        self.url = url
        self.address = address
        self.send_initial_post()

    def __send_initial_post(self):
        raise NotImplemented()


    ...
    

if __name__ == '__main__':


    # url, address = sys.argv[1], int(sys.argv[2], 16)
    # server = Server(url, address)

    print(encode_message_to_base64([13, 4097, 16383, 3, 3, 6, 1689164250000, 189]))
    string = input()
    [print(packet) for packet in decode_packets(string)]

