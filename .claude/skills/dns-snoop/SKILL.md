---
name: dns-snoop
description: Open recursive resolver assessment and DNS cache snooping. Use when asked to "snoop DNS cache", "assess a DNS resolver", "open resolver", "what are LAN clients browsing", "fingerprint dnsmasq/bind", "DNS recursion check", "cache snooping", or when recon finds an exposed DNS service (port 53) on a gateway/router/resolver.
---

# DNS Open-Resolver Assessment & Cache Snooping

When a target exposes DNS (port 53) — gateways, routers, internal resolvers, public
DNS — it is almost always the softest, most information-rich surface. This skill
covers fingerprinting, open-recursion detection, DNSSEC-validation detection, and
**cache snooping**: reading a resolver's cache to reveal what *other clients on the
network have been browsing* — banking, AI, adult, corporate SaaS — with **no auth and
no exploit required**.

Powered by `hot dns` (pure-socket DNS client — needs neither `dig` nor dnspython).

## Tool Reference

| Command | Purpose |
|---------|---------|
| `hot dns fingerprint --host <IP>` | Identify resolver software (version.bind / hostname.bind, CHAOS TXT) |
| `hot dns scan --host <IP>` | Full assessment: fingerprint + recursion + DNSSEC + snoop |
| `hot dns snoop --host <IP>` | Cache snooping only (RD=0) — reveal cached domains |
| `hot dns categories` | List snoop domain categories |

### Key options
- `-c, --category <name>` — target a context, repeatable. Categories: `banking_vn`,
  `banking_global`, `crypto`, `social`, `messaging`, `ai`, `shopping`, `streaming`,
  `adult`, `cloud_saas`, `dev`, `email`, `apple`, `infra`. Use `-c all` for everything.
- `-w, --wordlist <file>` — custom domain list (one per line) for targeted snooping.
- `--no-snoop` — `scan` does fingerprint/recursion/DNSSEC only.
- `--output <file>` — write structured JSON.
- `--port`, `--timeout`, `--workers` — standard knobs (default 53 / 2s / 20).

## How cache snooping works

A normal client query sets **RD=1** (recursion desired) — the resolver fetches the
answer. A snoop query sets **RD=0** (`+norecurse`): the resolver answers *only if the
name is already in its cache*. A non-empty answer therefore proves **another client
recently resolved that name**. Iterate a watchlist → reconstruct the network's
browsing profile. Zero auth, zero exploit, leaves the cache untouched.

## Workflow

```
1. Recon found port 53 open on <TARGET>?
     -> hot dns scan --host <TARGET> --output loot/dns.json

2. Read the summary:
     - software        -> map to CVEs (e.g. dnsmasq 2.90 -> VU#471747 / 6 CVEs)
     - open recursion  -> [HIGH] snooping + amplification surface
     - DNSSEC validating-> CVE surface for DNSSEC bugs (e.g. CVE-2026-4890/4891)

3. Targeted snoop for high-value context:
     -> hot dns snoop --host <TARGET> -c banking_vn -c banking_global -c crypto
     -> hot dns snoop --host <TARGET> -c infra        # mgmt/phone-home endpoints
     -> hot dns snoop --host <TARGET> -w custom.txt   # org-specific domains

4. Report cached banking / corp SaaS / sensitive domains as info disclosure.
```

## Decision tree

```
version.bind reveals software?
  yes -> research CVEs for that exact build; check recursion + DNSSEC surfaces
  no  -> still try recursion + snoop (software hidden != hardened)

open recursion = yes?
  yes -> [HIGH] cache snooping viable; if reachable off-LAN also amplification/DDoS reflector
  no  -> snoop may still work for the resolver's own clients; recursion refused for us

snoop hits include banking / corp SSO / sensitive?
  yes -> [HIGH] info disclosure: profile users' activity, target phished domains, time attacks
```

## Findings format

```
[HIGH] [<TARGET>] [Open resolver - DNS cache snooping]
- Finding: open recursive resolver (<software>) leaks cached lookups of other clients
- Evidence: hot dns snoop --host <TARGET> -c all  -> N/M cached incl. <bank>, <saas>
- Impact: unauthenticated profiling of every user's browsing (banking, sensitive sites)
- Next: map software -> CVEs; targeted snoop of org domains; consider cache-poison surface
```

## Remediation to recommend

1. Disable open recursion for untrusted clients (`localise-queries` / ACLs / views).
2. Suppress `version.bind` / `hostname.bind` disclosure.
3. Update the resolver (e.g. dnsmasq >= 2.92rel2 closes the May-2026 CVE set).
4. Randomise outbound query source port (`query-port=0`) to keep poisoning infeasible.

## Reuse as a library

```python
from hot_omelet.dns_recon import OpenResolver, wordlists
r = OpenResolver("203.0.113.53")
prof = r.assess()                       # fingerprint + recursion + dnssec + snoop
hits = r.snoop(wordlists.build_list(categories=["banking_vn", "ai"]))
```
The `hot_omelet/dns_recon/` package is dependency-free (pure socket) and works against
any resolver — drop it into other pipelines or the orchestrator's recon phase.
```
