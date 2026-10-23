---
name: firebase-audit
description: Audit Firebase projects for security rule misconfigurations. Use when you find Firebase config (API key, project ID, database URL) during review or source code analysis. Tests Realtime Database, Firestore, Storage, and Auth for open access.
---

# Firebase Security Rule Audit

When Firebase configuration is discovered, run this audit to identify misconfigured security rules. Firebase API keys are public by design - the real issues are in open security rules that allow unauthenticated access.

## Step 1: Extract Firebase Config

Firebase config is typically found in JavaScript bundles, mobile apps, or config files.

Required fields: `apiKey`, `authDomain`, `databaseURL`, `projectId`, `storageBucket`, `messagingSenderId`, `appId`.

## Step 2: Test Realtime Database

```bash
# Read check
curl -s "https://<project>-default-rtdb.<region>.firebasedatabase.app/.json?shallow=true"

# Write check (creates then removes test node)
curl -s -X PUT "https://<project>-default-rtdb.<region>.firebasedatabase.app/audit_test.json" -d '"test"'
curl -s -X DELETE "https://<project>-default-rtdb.<region>.firebasedatabase.app/audit_test.json"
```

## Step 3: Test Firestore

```bash
curl -s "https://firestore.googleapis.com/v1/projects/<project-id>/databases/(default)/documents"
```

## Step 4: Test Storage

```bash
curl -s "https://firebasestorage.googleapis.com/v0/b/<project-id>.appspot.com/o"
```

## Step 5: Test Auth

```bash
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api-key>" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}'
```

## Step 6: Report

Classify findings:
- CRITICAL: Data readable/writable without auth, open security rules
- HIGH: Anonymous account creation allowed
- MEDIUM: Storage bucket listable
- INFO: Structure information disclosed

## Common Misconfigurations

1. RTDB rules `{".read": true, ".write": true}` - full open access
2. Auth-only rules without validation - any authenticated user can access everything
3. Storage rules `allow read, write: if true` - open bucket
4. Firestore rules `allow read, write: if true` - open collections
5. Anonymous sign-up enabled + permissive rules

## Automated Audit

Save as `firebase_audit.py` and run: `python3 firebase_audit.py <project-id> <api-key> [database-url]`
