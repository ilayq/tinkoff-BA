from decode import decode_cmd_body


b = b"asd"
print(decode_cmd_body(1, 1, b))


b = b"envsensor01\x01\x05\xfflamp"
print(decode_cmd_body(2, 1, b))

b = b"\xff\x01\x05"
print(decode_cmd_body(2, 4, b))

b = b"asd\x01asd"
print(decode_cmd_body(3, 1, b))

b = b'\x01'
print(decode_cmd_body(4, 5, b))
