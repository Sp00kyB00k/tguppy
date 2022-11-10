import struct
from protocol import Protocol


class IPv4(Protocol):
    """
    Version                : 4 bits ( 1 / 2 byte )
    IHL                    : 4 bits ( 1 / 2 byte )
    Type of service        : 1 bytes
    Total Length           : 2 bytes
    Identification         : 2 bytes
    Flags                  : 2 bits ( 1 / 4 byte )
    Fragment offset        : 14 bits ( 14 / 8 byte )
    Time to live           : 1 byte
    Protocol               : 1 byte
    Header checksum        : 2 bytes
    Source IP address      : 4 bytes
    Destination IP address : 4 bytes
    Options                : 4 bytes
    """

    def __init__(self, buff: bytes):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xf
        self.tos = header[1]
        self.length = header[2]
        self.identification = header[3]
        self.flags = header[4] >> 6
        self.offset = header[4] & 0x4000
        self.ttl = header[5]
        self.protocol_number = header[6]
        self.checksum = header[7]
        self.src_address = header[8]
        self.destination_address = header[9]
        self.options = header[10]

    def next(self):
        return self.protocol_number


class ICMPv4(Protocol):
    """
    Type: 1 bytes
    Code: 1 byte
    Checksum: 2 bytes
    Rest of header: 4 bytes

    Due to ICMP being flexible, having different kinds of headers depending on the type of message
    Fun fact. It uses IP bit is considered part of the Internet Protocol Suite
    Layer 3 protocol depending on Layer 3 itself
    """

    def __init__(self, buff: bytes):
        header = struct.unpack('<BBH4s', buff)
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.other = header[3]


class IPv6(Protocol):
    def __init__(self):
        raise NotImplementedError


class ICMPv6(Protocol):
    def __init__(self):
        raise NotImplementedError
