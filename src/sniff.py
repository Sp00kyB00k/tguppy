import os
import socket

CONFIG = {
    'ETHII': (socket.AF_PACKET, socket.IPPROTO_RAW),
    'ICMP': (socket.AF_INET, socket.IPPROTO_ICMP),
    'IP': (socket.AF_INET, socket.IPPROTO_IPV4)
}


class HexFormatter:
    """
    Input: bytes or bytestring

    bytes get decoded and errors replaced with the Unicode <?> symbol U+FFFD
    HEX_FIlTER is a mapping for translating the bytes
    """
    HEX_FILTER = ''.join(
        [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

    def __init__(self, src: bytes):
        self.data = src.decode(errors='ignore')

    def hexdump(self, length=16, show=False):
        result = []
        for i in range(0, len(self.data), length):
            word = self.data[i:i+length]
            converted = word.translate(
                HexFormatter.HEX_FILTER).replace(chr(0xFFFD), '.')
            hexa = ' '.join([f'{ord(c):02X}' for c in word])
            hexwidth = int(os.get_terminal_size().columns / 2)
            result.append(f'{i:04x} {hexa:<{hexwidth}} {converted}')
        if show:
            for line in result:
                print(line)
            else:
                return result


class Sniffer:
    """
    Using raw socket to listen to all interfaces and all protocols
    """

    def __init__(self, mode='IP'):
        _conf = CONFIG[mode]
        self.socket_family = _conf[0]
        self.socket_type = socket.SOCK_RAW
        self.socket_proto = _conf[1]

    def run(self, amount=None):
        conn = socket.socket(self.socket_family,
                             self.socket_type, self.socket_proto)
        count = 0
        while True:
            buff = conn.recv(4096)
            print(buff)
            HexFormatter(buff).hexdump(show=True)
            if amount:
                if count >= amount:
                    break
            if Exception == KeyboardInterrupt:
                break
            count += 1
        conn.close()
