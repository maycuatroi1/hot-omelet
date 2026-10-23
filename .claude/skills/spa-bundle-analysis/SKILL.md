---
name: spa-bundle-analysis
description: Extract API endpoints, backend base URLs, auth flows, and hardcoded secrets from minified SPA JavaScript bundles (Vite/React/Vue and Next.js/Vercel). Use early on any frontend-heavy web assessment to build the roadmap for BFLA/IDOR/SSRF testing and credential harvesting - download the main bundle (or enumerate Next.js chunks), then grep for URLs, BaaS/cloud config, API keys, and auth headers. IMPORTANT: a clean static bundle does NOT mean the app is safe - the real attack surface is usually the authenticated API; see [[spa-authed-api-secret-disclosure]].
---

# SPA / Next.js bundle security analysis

Client-side JavaScript is the first thing the browser loads. Developers routinely
hardcode API base URLs, leak internal service hosts in error strings, and
accidentally ship `NEXT_PUBLIC_*` / `VITE_*` values (and sometimes real keys) into
compiled bundles. This is the fastest way to map a target's backend before you
touch it.

> **Scope note.** Bundle analysis is *recon*, not a verdict. Modern SPAs correctly
> keep secrets server-side, so a clean bundle is expected — it does **not** mean the
> app is hardened. Once you have the endpoint map, pivot to the authenticated API
> ([[spa-authed-api-secret-disclosure]]): open signup + over-serializing resource
> endpoints are where the critical secret-disclosure usually lives.

## When to use

- Assessing a Vite/React/Vue or Next.js SPA where backend paths live in shipped JS.
- Hunting for hardcoded endpoints, backend hostnames, BaaS config, or leaked keys.
- Building the endpoint list to feed into `hot web endpoints` / `hot web api`.

## Case A — generic SPA (Vite / React / Vue)

1. **Download the main bundle** — usually the largest `/assets/index-*.js` or `app-*.js`.
2. **Extract endpoints and base URLs**, hunt BaaS/cloud config, keys, and auth headers.

```bash
curl -sS -o index.js "https://app.example.com/assets/index-ABC.js"

# External URLs / API base
grep -oiE "https?://[a-z0-9._~:/?#@!$&'()*+,;=%-]+" index.js | sort -u
grep -oE 'baseURL[:"].*https?://[^"]+' index.js

# Quoted API paths (template-literal roots too)
grep -oE '"/[a-z][a-z0-9/_-]{2,40}"' index.js | sort -u

# BaaS / cloud config
grep -oiE "(firebase|supabase|railway\.app|vercel|amazonaws|googleapis)" index.js

# Hardcoded keys / tokens
grep -oiE "(AIza[A-Za-z0-9_-]{30,}|sk-[A-Za-z0-9_-]{30,}|pk_[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{32,}|eyJ[A-Za-z0-9_.]+)" index.js

# Auth patterns → tells you the auth scheme to replay
grep -oiE "Authorization.*Bearer|X-API-Key|X-CSRF|X-XSRF-TOKEN|withCredentials" index.js
```

Vite indicators: `VITE_API_URL`, `VITE_AUTH_*` exposed in build; template literals
`${var}` leak variable names; auth flow (`login`, `refresh`, `callback`) hardcoded.

## Case B — Next.js on Vercel (chunk enumeration)

Next.js splits code per-route, so the API call for a given page lives in that page's
chunk. Enumerate chunks via the build manifest, download all, then grep together.

```bash
# 1. Build ID from the root HTML
curl -s https://app.example.com/ | grep -oE '_next/static/[a-zA-Z0-9_-]{16,}/' | head -1
BUILD_ID="ebsQcfJhrDeCJewOsraB4"

# 2. Manifests enumerate the chunk list
curl -s "https://app.example.com/_next/static/${BUILD_ID}/_buildManifest.js"
curl -s "https://app.example.com/_next/static/${BUILD_ID}/_ssgManifest.js"
grep -oE 'chunks/[a-z0-9-]+\.js' webpack-*.js   # from the webpack chunk

# 3. Download all chunks and grep together
for c in $(grep -oE 'chunks/[a-z0-9-]+\.js' *.js | sort -u); do
  curl -s "https://app.example.com/_next/static/${BUILD_ID}/${c}" >> all_chunks.js
done
grep -roE 'https?://[a-z0-9.-]+(render|herokuapp|onrender|vercel|railway|api)[a-z0-9.-]*' all_chunks.js | sort -u
grep -oE 'NEXT_PUBLIC_[A-Z_]+' all_chunks.js | sort -u
grep -oE 'sk-or-v1-[a-zA-Z0-9]{32}|gsk_[a-zA-Z0-9]{32}|AIzaSy[a-zA-Z0-9_-]{33}' all_chunks.js
```

## 3. Confirm, don't assume

Cross-reference every discovered URL/endpoint with `curl`/Burp to confirm it exists
and its auth requirement. Discovered creds are tested immediately on other services
(credential stuffing). Discovered endpoints feed auth-bypass / IDOR / SSRF testing.

## Common findings

- **Backend base URL** — inlined as `NEXT_PUBLIC_API_URL` / `VITE_API_URL`; reveals
  infra (Render, Heroku, Railway, AWS).
- **Hardcoded keys** — Groq/OpenRouter/Gemini/Google keys in LLM-service chunks;
  Stripe `pk_`, Supabase/Firebase config.
- **Auth endpoints** — `/api/auth/google`, `/api/login`, `/api/verify` reveal the flow.
- **Env-vs-hardcoded** — `process.env.X` / `import.meta.env.X` is safe; a literal
  string value is the finding.

## Why it works

Bundles ship `NEXT_PUBLIC_*` / `VITE_*` for client runtime, and per-route splitting
means specific pages expose their backend calls. Unlike source review, bundle
analysis catches production-only config (dev=localhost, prod=real backend) and
secrets that were meant to be env-injected but got hardcoded. Then pivot to the
authenticated API — that's where the high-severity disclosure lives.
