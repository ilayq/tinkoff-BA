# TODO CLEAR TRASH BYTES AND CONVERT CMD_BODY


import base64
from dataclasses import dataclass


def decodeULEB128(byte_arr: bytes):
    value = 0
    shift = 0
    for byte in byte_arr:
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return value 

def encodeULEB128(val: int):
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
    return buf


@dataclass
class Payload:
    src: int 
    dst: int 
    serial: int 
    dev_type: int 
    cmd: int
    cmd_body: bytes


    def __iter__(self):
       ... 


@dataclass
class Packet:
    length: int
    payload: Payload
    crc8: int



if __name__ == '__main__':
    string = input()
    dcdstr = ''
    try:
        dcdstr = base64.urlsafe_b64decode(string + '==')
        print(dcdstr)
    except Exception as e:
        raise e

    
    shift = 0
    while shift < len(dcdstr):
        length = dcdstr[0 + shift]
        payload = dcdstr[1 + shift:length + shift + 1]
        crc = dcdstr[length + 1 + shift]
        pointer = 0
        src = payload[0]
        if payload[pointer + 1] < payload[pointer]:
            src = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        dst = payload[pointer]
        if payload[pointer + 1] < payload[pointer]:
            dst = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        pointer += 1
        serial = payload[pointer]
        if payload[pointer + 1] < payload[pointer]:
            serial = decodeULEB128(payload[pointer : pointer + 2])
            pointer += 1
        p = Payload(
                src=(src),
                dst=(dst),
                serial=serial,
                dev_type=payload[pointer],
                cmd=payload[pointer + 1],
                cmd_body=payload[pointer + 3 : length + 1]
                )
        shift += length + 2
        print(shift)

        print(Packet(length=length,
                    payload=p,
                    crc8=crc
            ))
