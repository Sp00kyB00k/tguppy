import struct
from protocol import Protocol

class EthernetII(Protocol):
    """
    Preamble              : 7 bytes
    Start Frame Delimiter : 1 byte
    MAC Destination       : 6 bytes
    MAC Source            : 6 bytes
    Ethertype             : 2 bytes
    Payload               : 46 to 1500 bytes
    Frame Sequence Check  : 4 bytes
    """

    ETHERTYPEVALUES = {'0x0800': 'IPv4', '0x0806': 'ARP', '0x86DD': 'IPv6'}
    PREAMBLE = bytes(b'10101010'*7)
    START_FRAME_DELIMITER = bytes(b'10101011')

    def __init__(self, buff: bytes):
        """
        Due to the raw packets not returning
        Preamble, Start Frame Delimeter and the Frame Sequence Check
        they are not attributes of this class
        """
        length = len(buff)
        buffer_format = '! 6s 6s 2s {}s'.format(str(length - 14))
        buffer = struct.unpack(buffer_format, buff)
        self.mac_destination = buffer[0] 
        self.mac_source = buffer[1]
        self.ethertype = buffer[2]
        self.payload = buffer[3]

    def __repr__(self) -> str:
        return """
        Destination: {}
        Source: {}
        Type: {}
        Payload: {}
        FCS: {}""".format(
                self.mac_destination.hex(':'),
                self.mac_source.hex(':'),
                self.ethertype,
                self.payload.hex(':')
                )

    def next(self) -> str:
        return self.ETHERTYPEVALUES[self.ethertype.hex()]


class ARP(Protocol):
    """
    Hardware Type: 2 bytes
    Protocol Type: 2 bytes
    Hardware Address Length: 1 byte
    Protocol Address Length: 1 byte
    Opcode: 2 bytes
    Sender Hardware Address: 6 bytes
    Sender Protocol Address: 4 bytes
    Target Hardware Address: 6 bytes
    Target Protocol Address: 4 bytes
    """

    def __init__(self, buff: bytes):
        buffer_format = '!2s 2s s s 2s 6s 4s 6s 4s'
        buffer = struct.unpack(buffer_format, buff)
        self.hrd = buffer[0]
        self.pro = buffer[1]
        self.hln = buffer[2]
        self.pln = buffer[3]
        self.op = buffer[4]
        self.sha = buffer[5]
        self.spa = buffer[6]
        self.tha = buffer[7]
        self.tpa = buffer[8]

    def __repr__(self) -> str:
        return """
        Hardware Type: {}
        Protocol Type: {}
        Hardware Address Length: {}
        Protocol Address Length: {}
        Opcode: {}
        Sender Hardware Address: {}
        Sender Protocol Address: {}
        Target Hardware Address: {}
        Target Protocol Address: {}
        """.format(
            self.hrd.hex(':'),
            self.pro.hex(':'),
            self.hln.hex(':'),
            self.pln.hex(':'),
            self.op.hex(':'),
            self.sha.hex(':'),
            self.spa.hex(':'),
            self.tha.hex(':'),
            self.tpa.hex(':')
        )
        
    def next(self):
        return None

