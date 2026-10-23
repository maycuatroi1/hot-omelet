---
name: cred-gather
description: Gather leaked credentials from external sources (GitHub, Google, breaches, paste sites). Usage /cred-gather <target domain or org>
---

# Credential Intelligence Gathering

Target: `$ARGUMENTS`

Gather leaked credentials from multiple external sources, build a custom wordlist, and optionally stuff against discovered services.

## Execution

Follow the **cred-gather** skill methodology:

1. **GitHub Dorking** - `gh search code` + WebSearch for leaked secrets in repos
2. **Google Dorking** - WebSearch for exposed configs, .env files, SQL dumps
3. **Breach Lookup** - HIBP API (if key available) + WebSearch for breach data
4. **Paste Sites** - WebSearch pastebin/gist for target credentials
5. **Git History** - truffleHog/gitleaks on discovered public repos
6. **Build Wordlist** - Merge all creds into `./workers/{target}/gathered_creds.txt`
7. **Credential Stuffing** - Try gathered creds against discovered services

## Output
- Credentials found per source
- Custom wordlist file path
- Stuffing results (if services already discovered)
