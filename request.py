import sys

import urllib.request


url, address = sys.argv[1], int(sys.argv[2], 16)


def send_request(url:str, msg: str) -> str:
    request = urllib.request.Request(url=url, data=msg.encode())
    print(urllib.request.urlopen(request).read().decode())





if __name__ == '__main__':
    send_request("http://localhost:9998", "DbMG_38BBgaI0Kv6kzGK")

