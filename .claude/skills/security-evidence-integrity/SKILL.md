---
name: security-evidence-integrity
description: Rules for packaging screenshot/PoC evidence in security advisories, bug bounty reports, and responsible-disclosure emails. The core rule is NO FABRICATED UI — browser screenshots must render the real target URL (not a custom HTML page you built to visualize the exploit), and terminal screenshots must contain real stdout bytes from real commands (ANSI-colorized is fine, fully-designed web "dashboard" is not). Use when preparing attachments for vendor security teams, H1/Bugcrowd reports, CVE disclosures, or any evidence package where a reviewer may dismiss fabricated-looking screenshots as "not real exploitation". Written after the Flink config-leak disclosure where the reporter initially submitted a styled HTML PoC page and had to redo screenshots against the real target UI.
---

# Security evidence integrity rules

## Rule 1 — Browser screenshots: render the actual target URL

**Don't** build `exploit.html` with your own title/branding showing "LEAKED: ..." in red text and call that the browser PoC. Reviewers rightly ignore it: the data being red is because your CSS colored it, not because the target exposed it.

**Do**:
- Navigate to the real target URL in Playwright / Puppeteer / Chromium.
- Let the native browser / native app UI render the leaked/vulnerable state.
- Screenshot that. E.g. Flink Dashboard at `/#/job-manager/config` showing the leaked `fs.oss.accessKeyId` in the stock operator view — no CSS of yours involved.

Acceptable browser screenshots:
- Target app's own rendered UI (dashboard, admin page, error page).
- Chromium's built-in JSON viewer at the raw API endpoint.
- Chromium DevTools Network panel showing response headers (screenshot browser chrome with real URL bar visible).
- `view-source:` of the target URL.

If you need a custom page to demonstrate cross-origin exploitability (CORS, CSRF), that's fine — but make it minimal plumbing (a `<button onclick="fetch(...)">`) and label it clearly as your harness, not as "the exploit UI". Screenshot the *result* of the fetch on the target, not a designed mockup of the result.

## Rule 2 — Terminal screenshots: bytes must be real

**Don't** render styled HTML in a browser, call it a "terminal", and screenshot that — reviewers can tell.

**Do** (any of these):
- Take a real desktop screenshot of your iTerm / gnome-terminal after running the command.
- If headless: capture ANSI stdout (`awk`, `sed` with `\x1b[…m`) and render to PNG with `ansi2png.py` (see sibling skill `ansi-terminal-to-png`). Bytes are real.
- `asciinema rec` + `agg` → PNG frame.
- `script -q -c "CMD" /dev/null` then post-process.

The rule: **the text content in the screenshot must have come from stdout of the real command**. Styling (font, background color, traffic lights) can be added; content can't be rewritten.

## Rule 3 — Don't mix evidence with interpretation

Keep screenshots minimal-label. Put interpretation ("this proves that X") in the email body or the report, not overlaid on the screenshot. A screenshot annotated with your own "VULN!" arrow is weaker evidence than a clean screenshot plus a report paragraph pointing at coordinates.

## Rule 4 — Include raw artifacts alongside screenshots

For every screenshot include the raw source in the zip:
- Screenshot of curl output → include the curl command + raw stdout `.txt`.
- Screenshot of browser page → include the raw HTTP response `.json` / `.html`.
- Screenshot of config file → include the config file.

Reviewers often re-run the command themselves. Make it frictionless.

## Rule 5 — Directory convention

```
submission/
├── email.md                       # ready-to-copy disclosure email
└── attachments/
    ├── <slug>-poc.zip             # self-contained reproducer (README + conf + script + raw output)
    ├── patch.diff                 # optional: suggested fix + test against the upstream repo
    ├── terminal_raw.txt           # ANSI source used for terminal screenshot(s)
    └── screenshots/
        ├── 01_terminal_*.png
        ├── 02_browser_*.png
        └── ...
```

`email.md` references attachments by their in-zip paths so the recipient can map them 1:1.

## Rule 6 — Redact PII in repro config, NOT in screenshots

Use obviously-fake placeholders in repro config (`AKIA_POC_LEAK_1234567890`, `LTAI_POC_OSS_ACCESSKEYID`, `poc_secret_SHOULD_BE_REDACTED_*`). Then your screenshots legitimately show those values cleartext — no follow-up "but wait, is that a real key?" question from the security team.

Never screenshot real production credentials. Ever. Even if the bug is real.

## Checklist before sending

- [ ] All browser screenshots show either the target's native UI or the raw target response (not my harness UI).
- [ ] All terminal screenshots have text content that's 1:1 with raw stdout included in the zip.
- [ ] No production credentials / real PII in any artifact.
- [ ] Every screenshot has a matching raw-data file in the zip.
- [ ] Zip has a `README.md` with a one-command repro.
- [ ] Patch diff included if the fix is trivial.
