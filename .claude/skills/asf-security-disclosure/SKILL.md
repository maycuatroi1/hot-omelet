---
name: asf-security-disclosure
description: Template and process for reporting a security finding to an Apache Software Foundation project (Flink, Spark, Airflow, Kafka, NiFi, Tomcat, etc). Covers the official email channels, expected tone/structure, attachments layout, how to maximize CVE-acceptance odds (ship patch + tests), and realistic expectations when the project's security model treats the affected surface as "deploy behind firewall". Use when you've validated a real bug in an ASF project and need to send a first-contact disclosure email.
---

# ASF responsible-disclosure workflow

## Channels

- **Primary**: `security@<project>.apache.org` — public PMC security alias.
  - Flink: `security@flink.apache.org`
  - Spark: `security@spark.apache.org`
  - Airflow: `security@airflow.apache.org`
- **Cc (optional but recommended)**: `private@<project>.apache.org` for PMC visibility.
- **Never**: public JIRA, GitHub issue, mailing list, Twitter. Violating this almost always disqualifies a CVE.

ASF projects are CNAs, so CVEs are issued by the PMC via MITRE or directly, usually at advisory-publish time.

## Pre-flight checks

1. **Duplicate search**: grep `https://<project>.apache.org/security.html`, `cvedetails.com`, MITRE search, the project's JIRA for similar terms. Note any prior similar CVE in your email (shows due diligence).
2. **Reproduce on current master** AND **latest stable release**. Advisories only cover released versions.
3. **Ensure repro is minimal**: single docker run, no proprietary deps, no real credentials.
4. **Do NOT test against someone else's cluster.** Your own container only.

## Email structure (humanized, not a report)

Write as a peer engineer emailing another engineer. Avoid "VULNERABILITY REPORT" all-caps, avoid CVSS numerology in the first paragraph, avoid demanding CVE assignment.

```
Subject: [SECURITY] <one-line summary> (<project> <affected-versions>)

Hi <Project> PMC / Security team,

I'm <name>, <role> at <org>. While <context — lab exercise / pentest engagement /
bug bounty recon>, I ran into what I believe is <small-but-real issue> in <component>.
I wanted to share it privately first and include a patch you can pick up quickly.

Short version:
- <2-4 bullet points of the mechanism>
- <why it matters>
- <what's NOT the issue — e.g. "I'm aware REST is unauthenticated by default; that's not what I'm reporting">

## Reproduction
Tested on <docker image / release>, also confirmed on master commit <hash>.
<one-command repro using the docker image>
<expected output>

Attached: <zip> with full repro, plus two screenshots:
1. <terminal shot showing X>
2. <native app UI shot showing Y>

## Proposed fix
Patch attached (<path.diff>). <one paragraph describing the change>.
Happy to open this as a PR under the appropriate JIRA when you give the go-ahead — 
I wanted to send it privately first rather than file in the open tracker.

## Scope
I haven't tried to abuse this beyond <minimal repro>. No third-party deployments 
or credentials were touched.

## Requested disclosure handling
- Please treat as non-public until a fix ships.
- I'd like to be credited as <name>, <org> in the advisory if a CVE is assigned, 
  but if the PMC decides this is a hardening item rather than CVE-worthy, 
  that's fine by me.
- Happy to iterate on the patch or investigate adjacent modules if useful.

Thanks for everything you do on <project>.

Best,
<name>
<role>, <org>
<email>
```

## Why this tone works

- **Peer-voice**: "I'm aware X is documented behavior; that's not what I'm reporting" signals you read the security model. PMCs get many reports from people who don't.
- **Self-deprecating on severity**: "small but real", "happy if you treat as hardening" — trades perceived fawning for credibility.
- **Patch attached**: removes 80% of the work. Projects are volunteer-run; a drive-by report with no fix has a high cost. A report WITH patch + tests has near-zero cost.
- **"Happy to open as PR when you give the go-ahead"**: shows you know the disclosure etiquette (don't open a public PR before the embargo).

## Attachments layout

See sibling skill `security-evidence-integrity` for the `submission/attachments/` convention.

Typical zip contents for an ASF disclosure:
```
<project>-<slug>-poc/
├── README.md                  one-command repro
├── <project>-conf.yaml        placeholder creds / triggering config
├── run_poc.sh                 reproducer against official docker image
├── raw_response.json          captured target response
├── terminal_raw.txt           ANSI source for the terminal screenshot
├── patch.diff                 minimal patch + new unit tests against master
└── FULL_REPORT.md             longer technical write-up (optional)
```

## Expectations

Honest calibration:

| Finding type | CVE odds | Advisory odds |
|---|---|---|
| Auth bypass in authenticated endpoint | high | high |
| Unauth RCE in default-auth-off endpoint, NOT documented | high | high |
| Unauth info disclosure, incomplete redaction, documented unauth surface | medium | medium-high |
| Hardening default (e.g. CORS=*, default TLS off) alone | low | low |
| Complicated chain with many prerequisites | low-medium | medium |

- **Timeline**: 0–7 days ack, 2–8 weeks patch, 30–90 day embargo.
- **Silence after 2 weeks**: lightly follow up. After 45 days: you can request CVE from MITRE directly as "independent researcher" if needed.
- **"Not a vulnerability" response**: usually means they consider it a hardening improvement. Ask politely if they'd still take the patch via JIRA.

## Don't

- Don't include "I think this deserves CVSS 9.8" in the first email.
- Don't CC media, Twitter, or non-ASF security aliases.
- Don't demand a bounty (ASF doesn't pay).
- Don't push to disclose publicly before the fix ships. You lose the CVE and burn the relationship.
- Don't blog about it before public advisory, even with names redacted.

## Related skills

- `security-evidence-integrity` — how to package screenshots/PoC without fabrication.
- `ansi-terminal-to-png` — terminal screenshot in a sandbox.
