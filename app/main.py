import socket
import struct

class DNSHeader:
    def __init__(self):
        self.id = 1234
        self.qr = 1
        self.opcode = self.aa = self.tc = self.rd = self.ra = self.z = self.rcode = 0
        self.ancount = self.qdcount = 1
        self.nscount = self.arcount = 0

    def to_bytes(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | (self.rcode)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )


def encode_str_to_bytes(data) -> bytes:
    parts = data.split('.')
    result = b''
    for part in parts:
        length = len(part)
        result += length.to_bytes(1, byteorder='big') + part.encode()
    result += b'\x00'
    return result

class DNSQuestion:
    def __init__(self, domain: str, qtype : str = 1, qclass : str = 1) -> None:
        self.qname = self.encode(domain)
        self.qtype = qtype
        self.qclass = qclass

    def encode(self, domain : str) -> bytes:
        return encode_str_to_bytes(domain)

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack('!HH', self.qtype, self.qclass)


class DNSAnswer:
    def __init__(self, name, ip) -> None:
        self.name = self.encode(name)
        self.type = (1).to_bytes(2, byteorder='big')
        self.aclass = (1).to_bytes(2, byteorder='big')
        self.ttl = (60).to_bytes(4, 'big')
        self.length = (4).to_bytes(2, 'big')
        self.data = self.ip_to_bytes(ip)

    def encode(self, data : str) -> bytes:
        return encode_str_to_bytes(data)

    def ip_to_bytes(self, ip : str) -> bytes:
        res = b''
        for part in ip.split('.'):
            res += int(part).to_bytes(1, 'big')

        return res
    
    def to_bytes(self):
        return self.name + self.type + self.aclass + self.ttl + self.length + self.data


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 2053))
        while True:
            try:
                data, addr = s.recvfrom(512)
                print(f'Received data from {addr}: {data}')
                header = DNSHeader()
                domain = 'codecrafters.io'
                q = DNSQuestion(domain)
                a = DNSAnswer(domain, '8.8.8.8')
                s.sendto(header.to_bytes() + q.to_bytes() + a.to_bytes(), addr)
            except Exception as e:
                print(f'Error receiving data: {e}')
                break

if __name__ == "__main__":
    main()
