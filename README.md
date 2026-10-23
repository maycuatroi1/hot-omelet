# Hot Omelet

An offensive security toolkit with an agent skill library, built for **authorized**
penetration testing and security research. The `hot` CLI wraps reconnaissance,
service exploitation and network tooling behind a lazy-loaded click command tree;
the `.claude/skills/` library packages the same workflows as on-demand instructions
for AI coding agents.

> **Authorized use only.** Every command in this toolkit is intended for targets you
> own or have written permission to test (engagements, CTF/lab environments, your own
> infrastructure). You are responsible for complying with the laws that apply to you.

## What's inside

| Area | Commands | Notes |
|------|----------|-------|
| Recon | `hot scan`, `hot dns`, `hot censys`, `hot web`, `hot github` | nmap/katana wrapper, DNS cache snooping, web enum |
| Services | `hot redis`, `hot mongo`, `hot pgsql`, `hot airflow`, `hot minio`, `hot supabase` | default-credential audits, data extraction, CVE checks |
| Network | `hot net`, `hot cf`, `hot camera`, `hot ssrf` | host discovery, ARP tools, MITM helpers, IP camera assessment |
| Load | `hot dos`, `hot beam` | exposure assessment + owned-infra stress testing |
| Chaining | `hot mass-pwn`, `hot assess`, `hot attack`, `hot 0-day` | automated lab chains and engagement workflows |
| Utilities | `hot wordlist`, `hot bf`, `hot apk`, `hot proxy`, `hot install` | context-aware wordlists, APK pulls, tool installer |

Two Rust companions live in `tools/rust/` (`hot-beam`, `hot-bf`) and are built on demand.

## Installation

```bash
pip install -e .          # base install (CLI + core commands)
pip install -e .[full]    # adds scapy, mitmproxy, playwright, psycopg2, minio, ...
pip install -e .[dev]     # adds pytest, ruff for development
```

## Development

```bash
make lint          # ruff check hot_omelet (must pass with 0 errors)
make test          # pytest smoke + unit tests
make build-rust    # compile tools/rust/hot_beam_rs + hot_bf_rs
./init.sh          # one-shot: install package + smoke-test the CLI
```

## Usage

### Scan a target with nmap and katana

```bash
hot https://example.com
```

### Scan the local network

```bash
hot net hosts --network 192.168.1.0/24
```

### Audit a Redis server

```bash
hot redis scan --host 10.0.0.1 --port 6379
hot redis dump --host 10.0.0.1
```

### Check PostgreSQL for default credentials

```bash
hot pgsql scan --host 10.0.0.1 --port 5432
```

### Generate a context-aware wordlist

```bash
hot wordlist -c example -d example.com -u admin,jdoe -k city -o example_wl.txt
```

### Install external tools automatically (needs `sudo` and `go` for katana)

```bash
hot install
```

## Agent skills

`.claude/skills/` holds 40+ SKILL.md playbooks (recon, SSRF, JWT, Supabase RLS audits,
Android dynamic analysis, evidence handling, ...). They work with Claude Code out of
the box and are plain Markdown, so any agent harness can consume them. Each skill
declares when to trigger in its frontmatter description.

`.claude/commands/` and `.claude/agents/` provide the matching slash commands and
sub-agent definitions for full assessments (`/assess`, `/attack`, `/recon`, `/validate`).

## Direct Ethernet link device discovery

| Command | Purpose |
|---------|---------|
| `hot net link-check <MAC>` | Check L2/L3 reachability to a device by MAC address. |
| `hot net link-setup` | Assign a static IP, ARP-sweep, and SSH-probe a direct link. |
| `hot net link-discover` | Passively sniff ARP/DHCP/mDNS to discover silent devices. |
| `hot net link-sweep` | ARP-sweep common private ranges to find a device with unknown subnet. |

```bash
sudo hot net link-check dc:a6:32:11:22:33 --iface en6
sudo hot net link-setup --iface en8 --net 192.168.1
hot net link-discover --iface en6 --duration 15
```

## License

MIT — see [LICENSE](LICENSE).
