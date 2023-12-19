import socket
import struct


class DNSHeader:
    def __init__(
        self,
        hid: int = 1234,
        qr: int = 1,
        opcode: int = 0,
        aa: int = 0,
        tc: int = 0,
        rd: int = 0,
        ra: int = 0,
        z: int = 0,
        rcode: int = 0,
        qdcount: int = 1,
        ancount: int = 1,
        nscount: int = 0,
        arcount: int = 0,
    ):
        self.id = hid
        self.qr = qr
        self.opcode = (
            self.aa
        ) = self.tc = self.rd = self.ra = self.z = self.rcode = rcode
        self.ancount = self.qdcount = qdcount
        self.nscount = self.arcount = arcount

    @staticmethod
    def from_bytes(message: bytes) -> "DNSHeader":
        # start & end indices in bytes
        start, end = (0, 6 * 2)
        header = message[start:end]
        hid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", header
        )
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        return DNSHeader(
            hid,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        )

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


def encode_str_to_bytes(data: str) -> bytes:
    parts = data.split(".")
    result = b""
    for part in parts:
        length = len(part)
        result += length.to_bytes(1, byteorder="big") + part.encode()
    result += b"\x00"
    return result


class DNSQuestion:
    def __init__(self, domain: str, qtype: str = 1, qclass: str = 1) -> None:
        self.qname = self.encode(domain)
        self.qtype = qtype
        self.qclass = qclass

    def encode(self, domain: str) -> bytes:
        return encode_str_to_bytes(domain)

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack("!HH", self.qtype, self.qclass)


class DNSAnswer:
    def __init__(
        self,
        name: str,
        ip: str,
        atype: int = 1,
        aclass: int = 1,
        ttl: int = 60,
        rdlength: int = 4,
    ) -> None:
        self.name = self.encode(name)
        self.type = (atype).to_bytes(2, byteorder="big")
        self.aclass = (aclass).to_bytes(2, byteorder="big")
        self.ttl = (ttl).to_bytes(4, "big")
        self.length = (rdlength).to_bytes(2, "big")
        self.rdata = self.ipv4_to_bytes(ip)

    def encode(self, data: str) -> bytes:
        return encode_str_to_bytes(data)

    def ipv4_to_bytes(self, ip: str) -> bytes:
        res = b""
        for part in ip.split("."):
            res += int(part).to_bytes(1, "big")

        return res

    def to_bytes(self) -> bytes:
        return self.name + self.type + self.aclass + self.ttl + self.length + self.rdata


def main():
    print("Starting UDP server...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 2053))
        while True:
            try:
                data, addr = s.recvfrom(512)
                print(f"Received data from {addr}: {data}")
                header = DNSHeader.from_bytes(data)
                # ovwerrite received flags for our reply
                header.qr, header.arcount, header.nscount = 1, 0, 0
                print(vars(header))
                domain = "codecrafters.io"
                q = DNSQuestion(domain)
                a = DNSAnswer(domain, "8.8.8.8")
                s.sendto(header.to_bytes() + q.to_bytes() + a.to_bytes(), addr)
            except Exception as e:
                print(f"Error receiving data: {e}")
                break


if __name__ == "__main__":
    main()
