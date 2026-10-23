---
name: github-public-repo-secret-mining
description: Discover hardcoded API keys, tokens, and sensitive config in public GitHub repositories before testing live systems. Use when a target has a public source repo (owner/repo) - enumerate the file tree via the GitHub API, then download and grep test files, screenshots, .env.example, and data files for committed secrets (sk-, gsk_, AIzaSy, mongodb+srv). Confirms whether leaked keys are live before assuming compromise. Companion CLI: `hot github secrets <owner/repo>`.
---

## When to use
Before probing a live backend, enumerate what secrets might be in the public source repository. Identifies: API keys that need rotating, hardcoded configuration, accidentally-committed test data, and credentials that could compromise live systems if still in use.

## How it works
1. **Verify repo is public**: `curl -s https://api.github.com/repos/OWNER/REPO | grep '"private"'`
2. **Fetch full file tree**: `curl -s https://api.github.com/repos/OWNER/REPO/git/trees/main?recursive=1` to enumerate all files at once
3. **Identify risky file patterns**: Filter for `.env`, config files, test files, images with key-like names, and well-known secret locations:
   - `backend/test_*.js|py` (often contain API key hardcoding for quick testing)
   - `*.png|.jpg` with "api" or "key" in filename (screenshots of API keys)
   - `.env.example` (reveals what secrets should exist)
   - `src/config/`, `src/data/`, `backend/src/data/` (hardcoded fallbacks)
4. **Download and grep candidate files**:
   - Test files: `curl https://raw.githubusercontent.com/OWNER/REPO/main/backend/test_*.js | grep -E "(api[_-]?key|sk_|gsk_|AIzaSy|mongodb|password)"`
   - Images: Download and inspect with OCR or manual review
   - Config: Scan for inline secrets vs env references
5. **Distinguish committed values from env references**: Hardcoded values are immediate risk; `process.env.API_KEY` is safe if `.env` is gitignored

## Example
```bash
REPO="INTELLICREW-AIaBLE/AIable_Champion"

# Step 1: Verify public
if curl -s "https://api.github.com/repos/$REPO" | grep -q '"private":false'; then
  echo "Repo is PUBLIC"
fi

# Step 2: Get full tree
curl -s "https://api.github.com/repos/$REPO/git/trees/main?recursive=1" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(x['path']) for x in d['tree']]"

# Step 3: Identify risky files
echo "Test files, images, data files:"
grep -E '(test_|_test\.|spec\.|\.(png|jpg|jpeg|gif)|/data/)' <<< $files

# Step 4: Download and inspect
for f in backend/test_google.js backend/src/data/api_tokens.json apigrogopenrouter.png; do
  curl -s "https://raw.githubusercontent.com/$REPO/main/$f"
done

# Step 5: Grep for patterns
grep -roE '(sk-[a-zA-Z0-9]{40,}|gsk_[a-zA-Z0-9]{32,}|AIzaSy[a-zA-Z0-9_-]{33}|mongodb\+srv://)' .
```

## Common findings
- **Test files** (`test_*.js`): Most common source of hardcoded keys — used for quick local testing, forgotten in history
- **Images** (*.png, *.jpg): Screenshots of API dashboards, curl commands, or configuration screens — extract keys via OCR
- **Fallback constants**: `const API_KEY = 'sk-...'` or `const SECRET = 'hoangbeo...'` in case env vars not set
- **Data files**: `api_tokens.json`, `credentials.json`, database dumps committed by mistake
- **Diff-visible history**: Even if main branch is clean, `git log` may show deleted secrets

## Why this approach
Public GitHub repos are scraped by automated scanners (yara, truffleHog, entropy checkers). If secrets are there, assume they are already compromised. Before testing prod, confirm: (1) secrets are actually live in production, (2) they haven't been rotated, (3) you understand the blast radius (test key vs prod key, API quota impact). Non-destructive discovery prevents false assumptions that compromise is confirmed when it may not be.
