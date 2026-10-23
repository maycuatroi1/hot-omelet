---
name: key-analyze
description: Analyze discovered API keys, tokens, and credentials to determine if they are actual misconfigurations or designed/expected behavior. Use when you find API keys, tokens, secrets, or credentials during reviews to avoid false positives.
---

# Key & Token Analysis

When you discover API keys or tokens during a review, evaluate whether they represent a real misconfiguration or are working as designed.

## Decision Framework

### Step 1: Classify the key type

**Public by design (skip):**
- Firebase API Key
- Google Analytics / GTM IDs
- Sentry DSN
- GCM/FCM Sender ID
- OAuth Client ID (mobile/SPA)
- Stripe Publishable Key (pk_)
- AppsFlyer Dev Key
- Certificate pin hashes

**Should be secret (report):**
- AWS Access Key (AKIA...)
- OAuth Client Secret
- Private keys (RSA/EC)
- JWT Secret/Signing Key
- Database connection strings
- Stripe Secret Key (sk_)
- Hardcoded passwords in config

### Step 2: Determine if it is a real misconfiguration

1. Is this key designed to be in the client? If yes, skip it
2. Does the key grant access beyond what the client should have? If yes, real finding
3. Is there a server-side misconfiguration? Test that, not the key itself
4. Is there a hardcoded secret? Real finding

### Step 3: What to actually test

Instead of reporting keys, test for misconfigurations:

| Service | What to Test |
|---------|-------------|
| Firebase RTDB | Open security rules |
| Firebase Storage | Open bucket |
| AWS S3 | Public bucket |
| AWS Cognito | Unauth role permissions |

### Step 4: Report only real findings

Report: hardcoded server-side credentials, exposed private keys, open security rules, public buckets with write access, database connection strings.

Do not report: Firebase API keys, analytics IDs, Sentry DSN, FCM Sender IDs, OAuth client IDs without secrets.
