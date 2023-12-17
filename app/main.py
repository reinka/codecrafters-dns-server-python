import socket
import struct

class DNSQuestion:
    def __init__(self, domain: str, qtype : str = 1, qclass : str = 1) -> None:
        self.qname = self.parse(domain)
        self.qtype = qtype
        self.qclass = qclass

    def parse(self, domain) -> bytes:
        parts = domain.split('.')
        result = b''
        for part in parts:
            length = len(part)
            result += length.to_bytes(1, byteorder='big') + part.encode()
        result += b'\x00'
        return result


    def to_bytes(self) -> bytes:
        return self.qname + struct.pack('!HH', self.qtype, self.qclass)

class DNSHeader:
    def __init__(self):
        self.id = 1234
        self.qr = 1
        self.opcode = self.aa = self.tc = self.rd = self.ra = self.z = self.rcode = 0
        self.ancount = self.nscount = self.arcount = 0
        self.qdcount = 1

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
            self.nscount,
            self.nscount,
            self.arcount,
        )


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
                header_bytes = header.to_bytes()
                q = DNSQuestion('codecrafters.io')
                msg_bytes = q.to_bytes()
                s.sendto(header_bytes + msg_bytes, addr)
            except Exception as e:
                print(f'Error receiving data: {e}')
                break

if __name__ == "__main__":
    main()
