from protocol.L2 import EthernetII
from protocol.L3 import ARP, IPv4, IPv6

class PDU:
    """
    Packet built according to OSI model
    
    Params:
    Input: Protocol
    Output: Packet
    """
    def __init__(self, buff: bytes):
        self.layer_2 = EthernetII(buff)
        match self.layer_2.ethertype:
            case 'ARP':
                self.layer_3 = ARP(self.layer_2.payload)
            case 'IPv4':
                self.layer_3 = IPv4(self.layer_2.payload)
            case 'IPv6':
                self.layer_3 = IPv6(self.layer_2.payload)
            case other:
                raise KeyError

