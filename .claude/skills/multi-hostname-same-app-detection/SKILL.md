---
name: multi-hostname-same-app-detection
description: Identify when several hostnames serve the same underlying web application by comparing JS bundle hashes, backend API base URLs, and shared/default credentials. Use when a target's scope lists multiple subdomains/hostnames and you want to avoid re-testing clones - if bundles hash-match and hit the same backend, one finding (auth bypass, default creds, IDOR) usually applies to all of them, so prioritize the shared backend. Complements [[spa-bundle-analysis]].
---

## Same-App Detection Across Multiple Hostnames

### When to Use
When targeting multiple hostnames in the same domain space (e.g., multiple `*.ptudev.net` subdomains, multiple staging/prod aliases), verify whether they are:
- Different applications (separate codebases, backends, scopes)
- Same application aliased across hostnames (identical frontend, shared backend, shared vulnerabilities)

### How It Works
1. **Frontend bundle fingerprint**: fetch SPA index.html, extract hashed bundle names (e.g., `index-ukZKv7Z7.js`). Identical hashes across hostnames = same app, same codebase version.
2. **Backend endpoint discovery**: enumerate API paths (`/api/*`, `/api-v1/*`, `/graphql`). Identical response signatures and paths indicate shared backend.
3. **Default credentials**: note any hardcoded or demo credentials (e.g., password fields, test accounts). Identical defaults suggest code sharing.
4. **Response headers**: X-Powered-By, Server, X-Backend-Version. Consistency confirms same application.

### Example

**Scenario**: Engaging `flipclass.ptudev.net` and `chat.ptudev.net` on the same day.

Recon finds:
- Both: Frontend bundle `index-ukZKv7Z7.js` (identical hash)
- Both: Backend `gw.university.edu/api`, `/api-v1` endpoints
- Both: Password menu `1234560Aa@` hardcoded

**Conclusion**: Same application, same codebase version. Findings from `chat.ptudev.net` carry over — inherited vulnerabilities, same authorization scope, same fix timeline.

### Why
In multi-hostname assessments, false negatives (treating same app as different targets) lead to duplicate exploitation and missed chaining. False positives (different apps treated as one) cause scope confusion. Bundle fingerprinting catches this deterministically.
