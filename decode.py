# TODO CLEAR TRASH BYTES AND CONVERT CMD_BODY


import base64
from dataclasses import dataclass
from typing import List


################################################################### ULEB128 ENCODING/DECODING AND crc8 ########################################################################################################################


def split_bytes_by_chunks(data: bytes):
    cur = [data[0]]
    for idx in range(1, len(data)):
        if data[idx] < data[idx - 1]:
            yield bytearray(cur)
            cur = [data[i]]
        else:
            cur.append(data[i])
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


@dataclass
class cmd_body_class:
    pass


@dataclass
class dev_props_class:
    pass


class device_class:
    dev_name: str
    dev_props: dev_props_class


################# Implementation #####################


@dataclass
class timer_cmd_6_body(cmd_body_class):
    timestamp: int


@dataclass
class timer_cmd_1_2_device_class(device_class):
    dev_name: str
    dev_props = None


@dataclass
class timer_cmd_1_2_body(cmd_body_class):
    dev_name: str
    device: timer_cmd_1_2_device_class


@dataclass
class smart_hub_cmd_1_2_device_class(device_class):
    dev_name: str
    dev_props = None 


@dataclass
class smart_hub_cmd_1_2_body(cmd_body_class):
    dev_name: str
    device: smart_hub_cmd_1_2_device_class


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
    devices: List[str]


@dataclass
class switch_cmd_4_body(cmd_body_class):
    is_enabled: bool


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


def decode_cmd_body(dev_type: int, cmd: int, cmd_body_bytes: bytes) -> cmd_body_class:
    match (dev_type, cmd):
        case (1, 1) | (1, 2):
            return smart_hub_cmd_1_2_body(dev_name=decodeULEB128(cmd_body_bytes))
        case (2, 1) | (2, 2):
            #decoded_string = decodeULEB128(cmd_body_bytes)
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


def decode_packets(string):
    dcdstr = ''
    try:
        dcdstr = base64.urlsafe_b64decode(string + '==')
    except Exception as e:
        raise e

    print(dcdstr) 
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
            
        dev_type = payload[pointer]
        cmd = payload[pointer + 1]


        cmd_body_bytes = payload[pointer + 3 : length + 1]

        p = Payload(
                src=(src),
                dst=(dst),
                serial=serial,
                dev_type=dev_type,
                cmd=cmd,
                cmd_body=payload[pointer + 3 : length + 1]
                )
        shift += length + 2

        yield Packet(length=length,
                      payload=p,
                      crc8=crc)


if __name__ == '__main__':
    string = input()
    [print(packet) for packet in decode_packets(string)]
    print(decodeULEB128(b"\x10\x20\x10"))
