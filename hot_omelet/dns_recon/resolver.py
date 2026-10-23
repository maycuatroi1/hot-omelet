"""`OpenResolver` - abstraction over a DNS resolver for open-resolver assessment.

Reusable across any target exposing DNS (gateways, public resolvers, internal
servers). Wraps the dependency-free dns_client and exposes the high-value
primitives discovered during the 10.202.2.1 engagement:

    r = OpenResolver("10.202.2.1")
    r.fingerprint()        # version.bind / hostname.bind
    r.check_recursion()    # open recursive resolver?
    r.check_dnssec()       # validating? (CVE-2026-4890/4891 surface)
    r.snoop(domains)       # F1: cache snooping -> other clients' activity
    r.assess()             # everything, as a structured dict
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import dns_client as dc
from . import wordlists

# A canary that virtually no one resolves; used to test recursion without
# benefiting from an already-cached popular name.
RECURSION_CANARY = "www.iana.org"
# Deliberately broken-DNSSEC zone: a validating resolver returns SERVFAIL.
DNSSEC_BROKEN = "dnssec-failed.org"


@dataclass
class SnoopHit:
    domain: str
    ip: str
    ttl: int


@dataclass
class ResolverProfile:
    host: str
    port: int
    reachable: bool = False
    software: Optional[str] = None          # version.bind
    hostname: Optional[str] = None          # hostname.bind
    recursion_open: Optional[bool] = None
    dnssec_validating: Optional[bool] = None
    snoop_hits: List[SnoopHit] = field(default_factory=list)
    snoop_total: int = 0

    def to_dict(self) -> Dict:
        return {
            "host": self.host, "port": self.port, "reachable": self.reachable,
            "software": self.software, "hostname": self.hostname,
            "recursion_open": self.recursion_open,
            "dnssec_validating": self.dnssec_validating,
            "snoop_total": self.snoop_total,
            "snoop_hits": [{"domain": h.domain, "ip": h.ip, "ttl": h.ttl}
                           for h in self.snoop_hits],
        }


class OpenResolver:
    def __init__(self, host: str, port: int = 53, timeout: float = 2.0, workers: int = 20):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.workers = workers

    # --- low level ---
    def _q(self, qname, qtype="A", qclass="IN", rd=True) -> dc.DNSResponse:
        return dc.query(self.host, qname, qtype, qclass, rd=rd,
                        port=self.port, timeout=self.timeout)

    def reachable(self) -> bool:
        return self._q("version.bind", "TXT", "CH").error is None

    # --- fingerprint ---
    def fingerprint(self):
        """Return (software, hostname) via CHAOS TXT version.bind/hostname.bind."""
        ver = self._q("version.bind", "TXT", "CH")
        host = self._q("hostname.bind", "TXT", "CH")
        return (ver.first(dc.QTYPE["TXT"]), host.first(dc.QTYPE["TXT"]))

    # --- recursion ---
    def check_recursion(self) -> Optional[bool]:
        """True if the resolver recurses for us (open resolver)."""
        r = self._q(RECURSION_CANARY, "A", rd=True)
        if r.error:
            return None
        # Open if it recurses (RA set) and actually returns an answer.
        return bool(r.ra and r.has_answer)

    # --- dnssec ---
    def check_dnssec(self) -> Optional[bool]:
        """True if the resolver validates DNSSEC (broken zone -> SERVFAIL)."""
        r = self._q(DNSSEC_BROKEN, "A", rd=True)
        if r.error:
            return None
        return r.rcode == 2  # SERVFAIL on a deliberately broken-signature zone

    # --- F1: cache snooping ---
    def snoop_one(self, domain: str) -> Optional[SnoopHit]:
        """RD=0 query: a non-empty answer means the name is already cached."""
        r = self._q(domain, "A", rd=False)
        if r.error or not r.has_answer:
            return None
        a = next((x for x in r.answers if x.rtype == dc.QTYPE["A"]), r.answers[0])
        return SnoopHit(domain=domain, ip=a.rdata, ttl=a.ttl)

    def snoop(self, domains: List[str]) -> List[SnoopHit]:
        """Cache-snoop a list of domains in parallel; return cached hits."""
        hits: List[SnoopHit] = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for res in ex.map(self.snoop_one, domains):
                if res:
                    hits.append(res)
        return hits

    # --- full assessment ---
    def assess(self, snoop_domains: Optional[List[str]] = None) -> ResolverProfile:
        prof = ResolverProfile(host=self.host, port=self.port)
        prof.reachable = self.reachable()
        if not prof.reachable:
            return prof
        prof.software, prof.hostname = self.fingerprint()
        prof.recursion_open = self.check_recursion()
        prof.dnssec_validating = self.check_dnssec()
        domains = snoop_domains if snoop_domains is not None else wordlists.DEFAULT
        prof.snoop_total = len(domains)
        prof.snoop_hits = self.snoop(domains)
        return prof
