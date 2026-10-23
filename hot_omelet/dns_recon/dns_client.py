"""Minimal dependency-free DNS client (pure socket + struct).

Built so the DNS reconnaissance tooling needs neither the `dig` binary nor
dnspython (which is broken in some environments). Supports the bits we need for
open-resolver assessment: arbitrary qtype/qclass, explicit RD (recursion-desired)
control for cache snooping, and parsing of A / AAAA / TXT / CNAME / NS / PTR / SOA.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

# qtype / qclass codes
QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "TXT": 16, "AAAA": 28, "ANY": 255}
QCLASS = {"IN": 1, "CH": 3}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class Answer:
    name: str
    rtype: int
    ttl: int
    rdata: str


@dataclass
class DNSResponse:
    rcode: int
    aa: bool       # authoritative answer
    tc: bool       # truncated
    ra: bool       # recursion available
    ad: bool       # authenticated data (DNSSEC)
    answers: List[Answer] = field(default_factory=list)
    raw: bytes = b""
    error: Optional[str] = None

    @property
    def rcode_name(self) -> str:
        return RCODE.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def has_answer(self) -> bool:
        return bool(self.answers)

    def first(self, rtype: Optional[int] = None) -> Optional[str]:
        for a in self.answers:
            if rtype is None or a.rtype == rtype:
                return a.rdata
        return None


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if label:
            lb = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
            out += bytes([len(lb)]) + lb
    out += b"\x00"
    return bytes(out)


def _decode_name(data: bytes, offset: int):
    """Decode a (possibly compressed) DNS name; return (name, next_offset)."""
    labels = []
    jumped = False
    next_off = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                next_off = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    if not jumped:
        next_off = offset
    return ".".join(labels), next_off


def build_query(qname: str, qtype: str = "A", qclass: str = "IN", rd: bool = True) -> bytes:
    qid = struct.unpack("!H", os.urandom(2))[0]
    flags = 0x0100 if rd else 0x0000  # RD bit
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack("!HH", QTYPE[qtype], QCLASS[qclass])
    return header + question


def _parse_rdata(rtype: int, data: bytes, rd_start: int, rd_len: int) -> str:
    chunk = data[rd_start:rd_start + rd_len]
    if rtype == 1 and rd_len == 4:                      # A
        return socket.inet_ntoa(chunk)
    if rtype == 28 and rd_len == 16:                    # AAAA
        return socket.inet_ntop(socket.AF_INET6, chunk)
    if rtype == 16:                                     # TXT
        out, i = [], 0
        while i < len(chunk):
            slen = chunk[i]
            out.append(chunk[i + 1:i + 1 + slen].decode("latin-1"))
            i += 1 + slen
        return " ".join(out)
    if rtype in (2, 5, 12):                              # NS / CNAME / PTR
        name, _ = _decode_name(data, rd_start)
        return name
    if rtype == 6:                                      # SOA
        name, _ = _decode_name(data, rd_start)
        return name
    return chunk.hex()


def parse_response(data: bytes) -> DNSResponse:
    if len(data) < 12:
        return DNSResponse(rcode=-1, aa=False, tc=False, ra=False, ad=False,
                           error="short response")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    resp = DNSResponse(
        rcode=flags & 0x000F,
        aa=bool(flags & 0x0400),
        tc=bool(flags & 0x0200),
        ra=bool(flags & 0x0080),
        ad=bool(flags & 0x0020),
        raw=data,
    )
    offset = 12
    for _ in range(qd):  # skip question section
        _, offset = _decode_name(data, offset)
        offset += 4
    for _ in range(an):
        try:
            _, offset = _decode_name(data, offset)
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = _parse_rdata(rtype, data, offset, rdlen)
            offset += rdlen
            name, _ = _decode_name(data, 12)
            resp.answers.append(Answer(name=name, rtype=rtype, ttl=ttl, rdata=rdata))
        except Exception:
            break
    return resp


def query(host: str, qname: str, qtype: str = "A", qclass: str = "IN",
          rd: bool = True, port: int = 53, timeout: float = 2.0) -> DNSResponse:
    """Send one UDP DNS query and return the parsed response (TCP fallback on TC)."""
    pkt = build_query(qname, qtype, qclass, rd)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (host, port))
            data, _ = s.recvfrom(4096)
        resp = parse_response(data)
        if resp.tc:  # retry over TCP
            return _query_tcp(host, qname, qtype, qclass, rd, port, timeout)
        return resp
    except socket.timeout:
        return DNSResponse(rcode=-1, aa=False, tc=False, ra=False, ad=False, error="timeout")
    except Exception as e:
        return DNSResponse(rcode=-1, aa=False, tc=False, ra=False, ad=False, error=str(e))


def _query_tcp(host, qname, qtype, qclass, rd, port, timeout) -> DNSResponse:
    pkt = build_query(qname, qtype, qclass, rd)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(struct.pack("!H", len(pkt)) + pkt)
            ln = struct.unpack("!H", s.recv(2))[0]
            buf = b""
            while len(buf) < ln:
                buf += s.recv(ln - len(buf))
        return parse_response(buf)
    except Exception as e:
        return DNSResponse(rcode=-1, aa=False, tc=False, ra=False, ad=False, error=str(e))
