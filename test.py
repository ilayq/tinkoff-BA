from decode import decode_cmd_body


b = b"envsensor01\x01\x05\xfflamp"
print(decode_cmd_body(2, 1, b))
