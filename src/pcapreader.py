import struct

class PCAPReader:
    """
    Class for reading the binary data stored in a .pcap file
    Input: Binary data 
    Output: ???
    """

    def __init__(self, path):
        self.path = path         
        with open(self.path, 'rb') as f:
            header_format = '4s 2s 2s 4s 4s 4s 4s'
            header = struct.unpack(header_format, f.read(24))
            self.magic_bytes = header[0].hex()
            self.major = header[1].hex()
            self.minor = header[2].hex()
            self.res1 = header[3]
            self.res2 = header[4]
            self.snaplen = header[5].hex()
            self.linktype = header[6] # the rest of the bits
            self.FCS = header[6] # first 4 bits
            self.f = header[6]   # fifth bit
            self.pos = f.tell()
            self.magic_bytes = PCAPReader.byteswap(self.magic_bytes)
            
    def read_packet(self):
        with open(self.path, 'rb') as f:
            f.seek(self.pos + 8)

    @staticmethod
    def byteswap(inp: bytes):
        result = bytes() 
        tmp1 = bytes.fromhex(inp)
        tmp2 = bytes.fromhex('ff')
        for data, swap in zip(tmp1, tmp2):
            result += bytes([data ^ swap])
        return data.hex()


p = PCAPReader('../data/test.pcap')
print(p.magic_bytes)
p.read_packet()
