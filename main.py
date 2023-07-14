import sys

import base64
from dataclasses import dataclass
from typing import Any, List
import time

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import urllib.request


import requests

SERIAL = 0
GLOBAL_ADDRESS = 0x3fff
DEVICE_POOL_BY_NAME = dict()
DEVICE_POOL_BY_ADDRESS = dict()
if __name__ == '__main__':
    URL = sys.argv[1]
    ADDRESS = int(sys.argv[2], 16)
NAME = "PORNHUB"
TIME = 0 


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
    return result


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
        # print(type(self.src))
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
    
    def __hash__(self):
        return hash(self.crc)


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
    status: bool

    def __bytes__(self):
        return bytes([self.status])


@dataclass
class lamp_and_socket_cmd_5_body(cmd_body_class):
    status: bool

    def __bytes__(self):
        return bytes([self.status])


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
    status: bool

    def __bytes__(self):
        return bytes([self.status])


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
            return switch_cmd_4_body(status=cmd_body_bytes[0])
        case (4, 1) | (4, 2) | (5, 1) | (5, 2):
            return lamp_and_socket_cmd_1_2_body(dev_name=cmd_body_bytes[1:].decode('utf8'))
        case (4, 3) | (5, 3):
            return None
        case (4, 4) | (5, 4):
            return lamp_and_socket_cmd_4_body(status=cmd_body_bytes[0])
        case (4, 5) | (5, 5):
            return lamp_and_socket_cmd_5_body(status=cmd_body_bytes[0])
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
        src = int(payload[0])

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            src = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        dst = int(payload[pointer])

        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            dst = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1


        serial = int(payload[pointer])
        # check if number represented with 2 bytes or 1
        if payload[pointer + 1] < payload[pointer] and payload[pointer] > 127:
            serial = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1 

        dev_type = int(payload[pointer])
        cmd = int(payload[pointer + 1])

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
        
        if crc != crc8(bytes(p)):
            raise WrongCRC8()
        
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

if __name__ == '__main__':
    PAYLOAD0x02 = Payload(
        src=ADDRESS,
        dst=GLOBAL_ADDRESS,
        serial=SERIAL,
        dev_type=1,
        cmd=2,
        cmd_body=smart_hub_cmd_1_2_body(
            dev_name=NAME
        )
    )

    PACKET0X02 = Packet(
        length=len(bytes(PAYLOAD0x02)),
        payload=PAYLOAD0x02,
        crc=crc8(bytes(PAYLOAD0x02))
    )



class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global SERIAL
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = post_data.decode()
        try:
            packets = decode_packets(data)
        except WrongCRC8:
            pass
        except Exception as e:
            raise e
        
        for packet in packets:
            self.handle_packet(packet)


        self.send_response(200)

        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def handle_packet(self, packet: Packet) -> None:
        global TIME
        match packet.payload.cmd:
            case 0x01: # whoishere
                self.send_post(PACKET0X02)
            case 0x02: # iamhere
                if packet.payload.src not in DEVICE_POOL_BY_ADDRESS:
                    DEVICE_POOL_BY_NAME[packet.payload.cmd_body.dev_name] = packet
                    DEVICE_POOL_BY_ADDRESS[packet.payload.src] = packet
                if packet.payload.dev_type in (2, 3, 4, 5):
                    p = Payload(
                        src=ADDRESS,
                        dst=packet.payload.src,
                        serial=SERIAL,
                        dev_type=1,
                        cmd=3,
                        cmd_body=None
                    )
                    response_packet = Packet(
                        length=len(bytes(p)),
                        payload=p,
                        crc=crc8(bytes(p))
                    )
                    self.send_post(response_packet)
                if packet.payload.dst != ADDRESS:
                    self.send_post(packet)
            case 0x03: # getstatus
                if packet.payload.dst == ADDRESS:
                    pass
                else:
                    self.send_post(packet)
            case 0x04: # status
                if packet.payload.dst == ADDRESS:
                    self.send_response(200)
                match packet.payload.dev_type:
                    case 1 | 6:
                        pass
                    case 4 | 5:
                        if packet.payload.dst == ADDRESS:
                            self.send_response(200)
                        else:
                            self.send_post(packet)
                    case 3:
                        if packet.payload.dst == ADDRESS:
                            self.send_response(200)
                            switch = DEVICE_POOL_BY_ADDRESS[packet.payload.src]
                            for device_name in switch.payload.cmd_body.dev_props:
                                device = DEVICE_POOL_BY_NAME.get(device_name, None)
                                if device:
                                    p = Payload(
                                        src=ADDRESS,
                                        dst=device.payload.src,
                                        serial=SERIAL,
                                        dev_type=device.payload.dev_type,
                                        cmd=5,
                                        cmd_body=packet.payload.cmd_body.status
                                    )
                                    response_packet = Packet(length=len(bytes(p)), payload=p, crc=crc8(bytes(p)))
                    case 2:
                        sensor = DEVICE_POOL_BY_ADDRESS.get(packet.payload.src, 0)
                        if not sensor:
                            return
                        pos = 0
                        sensors = sensor.payload.cmd_body.dev_props.sensors
                        triggers = sensor.payload.cmd_body.dev_props.triggers

                        # parse values into dict
                        is_having_sensor = {
                            'temperature':  (sensors >> 0) & 1,
                            'humidity':     (sensors >> 1) & 1,
                            'illumination': (sensors >> 2) & 1,
                            'pollution':    (sensors >> 3) & 1,
                        }
                        keys = ['temperature', 'humidity', 'illumination', 'pollution']
                        key_value = {}
                        # print(packet.payload.cmd_body)
                        for key in keys:
                            if is_having_sensor[key]:
                                key_value[key] = packet.payload.cmd_body.values[pos]
                                pos += 1
                        for trigger in triggers:
                            command = trigger.op & 1
                            condition = (trigger.op >> 1) & 1
                            cur_sensor = (trigger.op >> 2) & 0b11
                            sens_name = keys[cur_sensor]
                            value = trigger.value
                            name = trigger.name
                            connected_device = DEVICE_POOL_BY_NAME.get(name, 0)
                            if not is_having_sensor[sens_name] or not connected_device:
                                continue
                            match condition:
                                case 0:
                                    if key_value[sens_name] < value:
                                        p = Payload(
                                            src=ADDRESS,
                                            dst=connected_device.payload.src,
                                            serial=SERIAL,
                                            dev_type=connected_device.payload.dev_type,
                                            cmd=5,
                                            cmd_body=command
                                        )
                                        response_packet = Packet(
                                            length=len(bytes(p)),
                                            payload=p,
                                            crc=crc8(bytes(p))
                                        )
                                        self.send_post(response_packet)
                                case 1:
                                    if key_value[sens_name] > value:
                                        p = Payload(
                                            src=ADDRESS,
                                            dst=connected_device.payload.src,
                                            serial=SERIAL,
                                            dev_type=connected_device.payload.dev_type,
                                            cmd=5,
                                            cmd_body=command
                                        )
                                        response_packet = Packet(
                                            length=len(bytes(p)),
                                            payload=p,
                                            crc=crc8(bytes(p))
                                        )
                                        self.send_post(response_packet)

                    case _:
                        raise NotImplemented()
            case 0x05: # set status
                raise NotImplemented()
            case 0x06: # tick
                TIME = packet.payload.cmd_body.timestamp
                self.send_response(200)
            case _:
                raise NotImplemented()

    def log_message(self, asd, *args) -> None:
        return 

    def send_post(self, msg: Packet):
        global SERIAL
        msgbytes = base64.urlsafe_b64encode(bytes(msg)).decode().strip('=').encode()
        start = time.time()

        try:
            code = requests.post(url=URL, data=msgbytes).status_code
            SERIAL += 1
        except:
            if time.time() - start > 0.3:
                device = DEVICE_POOL_BY_ADDRESS[msg.payload.dst]
                del DEVICE_POOL_BY_ADDRESS[msg.payload.dst]
                del DEVICE_POOL_BY_NAME[device.payload.cmd_body.dev_name]

        if code == 200:
            return
        elif code == 204:
            sys.exit(0)
        else:
            sys.exit(99)
        

def send_initial_request(url=sys.argv[1], address=int(sys.argv[2], 16)):
    global SERIAL, TIME
    # WHOISHERE request
    SERIAL += 1
    payload = Payload(
        src=ADDRESS,
        dst=GLOBAL_ADDRESS,
        serial=SERIAL,
        dev_type=1,
        cmd=1,
        cmd_body=smart_hub_cmd_1_2_body(
            dev_name=NAME
        )
    )

    packet = Packet(
        length=len(bytes(payload)),
        payload=payload,
        crc=crc8(bytes(payload))
    )

    msg = base64.urlsafe_b64encode(bytes(packet)).decode()
    request = urllib.request.Request(url=url, method="POST", data=msg.strip('=').encode())
    try:
        s = urllib.request.urlopen(request).read().decode()
    except Exception as e:
        raise e 
    packets = list(decode_packets(s))
    for pack in packets:
        if pack.payload.cmd == 6:
            TIME = pack.payload.cmd_body
            break
    for pack in decode_packets(s):
        if pack.payload.cmd == 2:
            DEVICE_POOL_BY_NAME[pack.payload.cmd_body.dev_name] = pack
            DEVICE_POOL_BY_ADDRESS[pack.payload.src] = pack
        elif pack.payload.cmd == 6:
            TIME = pack.payload.cmd_body
    # DEVICE_POOL.extend([pack for pack in decode_packets(s)])
    

if __name__ == '__main__':
    server = HTTPServer(server_address=('127.0.0.1', 8000), RequestHandlerClass=Handler)
    send_initial_request()
    # print(DEVICE_POOL_BY_ADDRESS)
    # print(SERIAL)
    server.serve_forever()

