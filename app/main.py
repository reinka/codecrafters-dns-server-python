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
    def from_bytes(message: bytes, qdcount: int) -> tuple[list['DNSQuestion'], int]:
        questions = []
        offset = 12  # Start after the header
        for _ in range(qdcount):
            domain, offset = DNSQuestion.parse_domain(message, offset)
            qtype, qclass = struct.unpack('!HH', message[offset:offset + 4])
            questions.append(DNSQuestion(domain, qtype, qclass))
            offset += 4
        return questions, offset
    
    @staticmethod
    def parse_domain(message: bytes, offset: int) -> tuple:
        return parse_domain(message, offset)


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
    
    @staticmethod
    def parse_domain(message: bytes, offset: int) -> tuple:
        return parse_domain(message, offset)
    
    @staticmethod
    def from_bytes(message: bytes, offset: int, ancount: int) -> tuple[list['DNSAnswer'], int]:
        answers = []
        for _ in range(ancount):
            name, offset = DNSAnswer.parse_domain(message, offset)
            atype, aclass, ttl, rdlength = struct.unpack('!HHIH', message[offset:offset + 10])
            offset += 10  # Advance offset past these fields
            rdata = message[offset:offset + rdlength]
            
            # If type is A (1), convert rdata to an IP address
            if atype == 1:
                ip = '.'.join(map(str, rdata))
            else:
                ip = ''  # Other record types not handled in this example

            answers.append(DNSAnswer(name, ip, atype, aclass, ttl, rdlength))
            offset += rdlength

        return answers, offset

def forward_dns_query(query: bytes, dns_server: str, dns_port: int = 53) -> bytes:
    # Create a socket to communicate with the DNS server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
        dns_socket.settimeout(2)  # Set a timeout for the DNS query
        # Send the DNS query to the specified DNS server
        dns_socket.sendto(query, (dns_server, dns_port))
        # Receive the response from the DNS server
        response, _ = dns_socket.recvfrom(4096)
    return response

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", required=False, default=None)
    args = parser.parse_args()
    print("Starting UDP server...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 2053))
        while True:
            data, addr = s.recvfrom(512)
            # h1 = DNSHeader.from_bytes(data)
            # data = b'\xc0\x90\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'
            print(f"Received data from {addr}: {data}")
            query_header = DNSHeader.from_bytes(data)

            # Parsing the question section
            query_questions, questions_offset = DNSQuestion.from_bytes(data, query_header.qdcount)
            response_header = DNSHeader(
                hid=query_header.id,  # Match the query's ID
                qr=1,  # This is a response
                opcode=query_header.opcode,
                aa=0,
                tc=0,  # Not truncated
                rd=query_header.rd,
                ra=0,  # Recursion not available
                z=0,
                rcode=0 if not query_header.opcode else 4,
                qdcount=query_header.qdcount,
                ancount=len(query_questions),  # Assuming one answer per question
                nscount=0,
                arcount=0
            )

            if args.resolver:
                host, port = args.resolver.split(":")
                port = int(port)
                aggregated_answers = []

                for question in query_questions:
                    # Forward each question separately
                    fw_header = DNSHeader(
                        hid=query_header.id,  # Keep the original ID
                        qr=0,  # Query
                        opcode=query_header.opcode,
                        aa=0,
                        tc=0,
                        rd=query_header.rd,
                        ra=0,
                        z=0,
                        rcode=0,
                        qdcount=1,  # Only one question
                        ancount=0,
                        nscount=0,
                        arcount=0
                    )
                    fw_query = fw_header.to_bytes() + question.to_bytes()
                    fw_response = forward_dns_query(fw_query, host, port)

                    # Parse the response and aggregate answers
                    fw_header_res = DNSHeader.from_bytes(fw_response)
                    offset = 12  # Start after the header
                    _, offset = DNSQuestion.from_bytes(fw_response, fw_header_res.qdcount)  # Skip questions
                    fw_answers, _ = DNSAnswer.from_bytes(fw_response, offset, fw_header_res.ancount)
                    aggregated_answers.extend(fw_answers)

                # Construct the final response
                response_header.qdcount = query_header.qdcount
                response_header.ancount = len(aggregated_answers)
                response = response_header.to_bytes() + data[12:questions_offset]
                for answer in aggregated_answers:
                    response += answer.to_bytes()
            else:

                # Constructing the question section for the response
                response_questions = b''.join(q.to_bytes() for q in query_questions)

                # Constructing the answer section
                response_answers = b''
                for q in query_questions:
                    if q.qtype == 1:  # Process if QTYPE is A
                        a = DNSAnswer(q.domain, "8.8.8.8", q.qtype, q.qclass)
                        response_answers += a.to_bytes()

                # Assembling the full response
                response = response_header.to_bytes() + response_questions + response_answers
            print(f'response is {response}')
            print(f'Sending response to {addr}')
            s.sendto(response, addr)


if __name__ == "__main__":
    main()
