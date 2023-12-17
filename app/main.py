import socket
import struct

class DNSHeader:
    def __init__(self):
        self.id = 1234
        self.qr = 1
        self.opcode = self.aa = self.tc = self.rd = self.ra = self.z = self.rcode = 0
        self.qdcount = self.ancount = self.nscount = self.arcount = 0

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
            ">HHHHHH",
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
                data, addr = s.recvfrom(1024)
                print(f'Received data from {addr}: {data}')
                header = DNSHeader()
                header_bytes = header.to_bytes()
                s.sendto(header_bytes, addr)
            except Exception as e:
                print(f'Error receiving data: {e}')
                break

if __name__ == "__main__":
    main()
