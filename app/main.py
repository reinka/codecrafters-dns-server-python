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
        self.opcode = opcode
        self.aa = aa
        self.tc = tc 
        self.rd = rd
        self.ra = ra 
        self.z = z 
        self.rcode = rcode
        self.ancount = ancount
        self.qdcount = qdcount
        self.nscount = nscount
        self.arcount = arcount

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
    def __init__(self, domain: str, qtype: int = 1, qclass: int = 1) -> None:
        self.qname = self.encode(domain)
        self.qtype = qtype
        self.qclass = qclass
        self.domain = domain

    def encode(self, domain: str) -> bytes:
        return encode_str_to_bytes(domain)

    def to_bytes(self) -> bytes:
        return self.qname + struct.pack("!HH", self.qtype, self.qclass)

    @staticmethod
    def from_bytes(message: bytes) -> list['DNSQuestion']:
        questions = []
        offset = 12  # Start after the header
        while offset < len(message):
            domain, offset = DNSQuestion.parse_domain(message, offset)
            if offset + 4 <= len(message):  # Ensure enough bytes for QTYPE and QCLASS
                qtype, qclass = struct.unpack('!HH', message[offset:offset + 4])
                questions.append(DNSQuestion(domain, qtype, qclass))
                offset += 4
            else:
                break
        return questions
    
    @staticmethod
    def parse_domain(message: bytes, offset: int) -> tuple:
        labels = []
        while True:
            length = message[offset]
            if length & 0xC0 == 0xC0:  # Check for compression
                pointer = struct.unpack("!H", message[offset:offset+2])[0]
                offset += 2
                pointer &= 0x3FFF  # Remove the compression flag bits
                part, _ = DNSQuestion.parse_domain(message, pointer)
                labels.append(part)
                return '.'.join(labels), offset

            offset += 1  # Skip the length byte
            if length == 0:  # End of the domain name
                break

            labels.append(message[offset:offset+length].decode('utf-8'))
            offset += length

        return '.'.join(labels), offset


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
            data, addr = s.recvfrom(512)
            print(f"Received data from {addr}: {data}")
            header = DNSHeader.from_bytes(data)
            header.qr, header.ancount, header.arcount, header.nscount = 1, 0, 0, 0
            header.rcode = 0 if not header.opcode else 4

            questions = DNSQuestion.from_bytes(data)
            response_body = b''
            for q in questions:
                if q.qtype == 1:  # Only process if QTYPE is A
                    response_body += q.to_bytes()
                    a = DNSAnswer(q.domain, "8.8.8.8", q.qtype, q.qclass)
                    response_body += a.to_bytes()
                    header.ancount += 1

            response = header.to_bytes() + response_body
            s.sendto(response, addr)


if __name__ == "__main__":
    main()
