---
name: spa-authed-api-secret-disclosure
description: When a Next.js / Vite SPA looks "hardened" from the outside (anon routes 307 -> /login, no secrets in the static bundle), the real attack surface is the AUTHENTICATED resource API. Two compounding flaws turn this into a critical secret-disclosure: (1) open email self-signup with no verification gate lets any internet user get a session in seconds, and (2) resource-management endpoints (`/api/llms`, `/api/integrations`, `/api/connections`, `/api/agents`, `/api/datasources`) serialize server-side secrets - provider apiKey, DB connection strings, webhook tokens, system prompts - straight into the JSON response. Minified bundles hide the API paths, so register an account and drive the app with Playwright to capture the real XHR calls, then replay them with fetch(credentials:'include'). Use when a SPA/Next.js admin or "hub"/"dashboard"/"management" app resists static review but has open or weak signup.
---

# SPA authenticated-API secret disclosure (open-signup pivot)

Proven on `aihub.jsclub.dev` (JS Club AI Hub): app graded "hardened" on static
review, but open signup + `GET /api/llms` returned a live OpenAI-compatible
`apiKey` in plaintext to a brand-new unverified account. Static-only review
missed it entirely because the data-layer paths were buried in minified chunks.

## Why static review under-rates these apps

- Anon homepage 307 -> `/login`, `get-session` returns `null`, `list-sessions`
  401 -> looks correctly gated.
- The static bundle has no secrets (correct - they live server-side).
- Minified Next.js chunks don't expose API paths to grep; the OAuth-provider URL
  lists from `better-auth`/social SDKs are false positives, not the app's routes.
- Conclusion "clean" is premature: you never exercised the authenticated API.

## The workflow

1. Test for open signup (no email verification gate):
   ```bash
   A="https://target"
   # better-auth shape:
   curl -sk -X POST "$A/api/auth/sign-up/email" -H "Content-Type: application/json" \
     -c /tmp/c.txt -d '{"name":"t","email":"poc+'$(date +%s)'@example.com","password":"PocPass123!x"}' -w "\n[%{http_code}]\n"
   curl -sk "$A/api/auth/get-session" -b /tmp/c.txt   # session with emailVerified:false == no gate
   ```
   Other shapes: NextAuth `/api/auth/callback/credentials`, Supabase GoTrue
   `/auth/v1/signup` (check `/auth/v1/settings` -> `disable_signup`, email provider on),
   Clerk, custom `/api/register`. If signup is invite-only, look for an open OAuth
   provider (Google) instead.

2. Find the REAL API by driving the authed app with Playwright (bundles are
   minified - do NOT waste time grepping chunks for paths):
   - Playwright: navigate `/login`, fill form, submit; the app routes you in.
   - Visit each sidebar tab (`/llms`, `/agents`, `/datasource`, `/integrations`,
     `/settings`...).
   - `browser_network_requests` with `static:false` filter `/(api|v1|rpc|graphql)/`
     -> the actual endpoints (e.g. `/api/agents?page=1&pageSize=10`).

3. Replay + enumerate from inside the page context (carries the httpOnly cookie):
   ```js
   await page.evaluate(async () => {
     const grab = async p => ({p, ...(await (await fetch(p,{credentials:'include'})).json().catch(()=>({})))});
     return [await grab('/api/llms?page=1&pageSize=100'),
             await grab('/api/agents?page=1&pageSize=100'),
             await grab('/api/llms/1'), await grab('/api/agents/1')];
   });
   ```

4. Grep the JSON responses for fields that must NEVER reach the client:
   `apiKey`, `api_key`, `secret`, `token`, `password`, `connectionString`,
   `dsn`, `privateKey`, `webhookSecret`, `clientSecret`, plus internal config
   like `systemPrompt`. Their presence = the finding.

5. Test horizontal access control: `/api/<resource>/{id}` with incrementing IDs
   from a second throwaway account -> IDOR if you read another tenant's secrets.

## Severity calculus

- Plaintext provider key returned to any registered user = **CRITICAL**
  (cost/quota abuse + the key works directly against the provider base URL).
- The fix is always: make secret fields write-only (never serialize), require
  email verification / invite-only, enforce per-resource authz. Always recommend
  ROTATING any key you observed.

## Rules of engagement

- Creating one or two throwaway accounts is acceptable PoC; note them in the
  report and ask the owner to delete them.
- Do NOT use a leaked provider key against the provider (that's real cost abuse /
  using stolen creds). The plaintext value in the API response IS the evidence.
- Save the raw response to `loot/` redacted in the report (key prefix...suffix).

## Related

- `supabase-rls-audit` (the SPA's other common backend; same "static looks clean"
  trap, different mechanism - anon REST role instead of authed session).
- `incomplete-secret-allowlist-audit` (server-side redaction gaps - sibling bug
  class where the secret leaks because the redaction list is incomplete).
