---
name: ai-cli-allowlist-harness
description: Audit AI coding agent command allow-list without building the full host app. Port the regex/rule logic into a minimal Node.js harness that uses the same tree-sitter grammar the target uses, then run bypass payloads through it. Use when assessing VSCode Copilot, Cursor, Claude Code, Codex CLI, or any agent that gates shell commands via regex-on-text.
---

# AI CLI Allow-list Audit Harness

## When to use

Any time the target is an AI coding assistant that:

- Accepts a shell command from the LLM
- Parses it with tree-sitter (bash / powershell / zsh)
- Runs each sub-command through an allow/deny regex set
- Silently auto-executes when all sub-commands are approved

Typical targets: VSCode `chat.tools.terminal.autoApprove`, Cursor agent tools, Claude Code `Bash` tool allow-list, Codex CLI, Copilot CLI, Aider, custom MCP servers.

Building the full IDE to test one regex class is a waste. This harness covers the decision with ~80 LOC.

## Why it works

The allow-list decision is a pure function of three ingredients, all of which are available off-repo:

1. Rule set — copy verbatim from source config (usually `*.ts`/`*.json` with regex strings).
2. Regex engine — V8 `RegExp` in Electron = Node.js `RegExp`. Identical.
3. Grammar — shipped as WASM on npm (`tree-sitter-bash`, `tree-sitter-powershell`, etc.).

So a Node.js script can reproduce the verdict byte-for-byte without building anything.

## Setup

```bash
mkdir harness && cd harness
cat >package.json <<'EOF'
{ "name": "harness", "private": true, "type": "module",
  "dependencies": { "web-tree-sitter": "^0.25.0" } }
EOF
npm install web-tree-sitter tree-sitter-bash
# Optional, only needed for PowerShell targets:
# npm install tree-sitter-powershell
```

## Template

```js
import { Parser, Language, Query } from 'web-tree-sitter';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

await Parser.init({ locateFile: () => 'node_modules/web-tree-sitter/tree-sitter.wasm' });
const parser = new Parser();
const lang = await Language.load(await readFile('node_modules/tree-sitter-bash/tree-sitter-bash.wasm'));
parser.setLanguage(lang);
const query = new Query(lang, '(command) @command');

// 1) Paste the target's entry-to-regex conversion verbatim.
function convertEntryToRegex(value) { /* port _doConvertAutoApproveEntryToRegex */ }

// 2) Paste the default rule set verbatim from target source.
const defaultRules = { /* ... */ };
const allow = [], deny = [];
for (const [k, v] of Object.entries(defaultRules)) {
  (v ? allow : deny).push({ rx: convertEntryToRegex(k), src: k });
}

function check(sub) {
  for (const r of deny)  if (r.rx.test(sub)) return { result: 'denied',  rule: r.src };
  for (const r of allow) if (r.rx.test(sub)) return { result: 'approved', rule: r.src };
  return { result: 'noMatch' };
}

const cases = [
  { name: 'baseline', cmd: 'find . -exec id {} +' },
  { name: 'bypass',   cmd: "find . '-exec' id '{}' +" },
];

for (const c of cases) {
  const subs = query.captures(parser.parse(c.cmd).rootNode).map(x => x.node.text);
  const results = subs.map(s => ({ s, r: check(s) }));
  const denied = results.some(x => x.r.result === 'denied');
  const allOk  = results.length && results.every(x => x.r.result === 'approved');
  console.log(c.name, denied ? 'DENIED' : allOk ? 'AUTO-APPROVED' : 'needs-user-approval', results);
}
```

## Validation Protocol

Every finding needs two checks:

1. **Parser-side**: harness reports `AUTO-APPROVED` or equivalent bypass verdict.
2. **Shell-side**: the payload, once quote-stripped by the shell, really produces the argv the attacker wants.

```bash
bash -c "set -- \"'-exec'\"; printf '%s\n' \"\$1\""
# must print: -exec
```

Without the shell-side check you have not proven the bypass reaches the real binary.

## Reference ports (copy-paste starters)

| Target | File to port from | Grammar |
|--------|-------------------|---------|
| VSCode Copilot terminal | `src/vs/workbench/contrib/terminalContrib/chatAgentTools/browser/tools/commandLineAnalyzer/autoApprove/commandLineAutoApprover.ts` (`_doConvertAutoApproveEntryToRegex`, `isCommandAutoApproved`) + defaults in `common/terminalChatAgentToolsConfiguration.ts` | tree-sitter-bash, tree-sitter-powershell |
| Claude Code | `Bash` tool allow/deny in settings.json + its parser (bash subset) | tree-sitter-bash |
| Cursor agent | `.cursor/rules/*` + internal tool config | tree-sitter-bash |

## Known pitfalls

- `web-tree-sitter` v0.25 changed API: `new Query(lang, source)`, not `lang.query(...)`. Older tutorials are wrong.
- Grammar wasm shipped inside `node_modules/<grammar>/` has a fixed filename (e.g. `tree-sitter-bash.wasm`). Load it directly with `readFile` + `Language.load(buffer)`.
- Target may pre-process the command line (e.g. VSCode `maskPwshFlagEquals`, cd-prefix rewriter). Port those *before* calling `parser.parse`.
- Tree-sitter does extract `(command)` nodes inside function bodies and command substitutions, so function-shadow and `$(...)` tricks are almost always caught. Don't assume otherwise without a harness run.
- `child_process` FD leak: prefer `execFileSync` with explicit `argv`, never `exec()` with interpolation.

## Example findings this caught in one session

- VSCode default deny `/^find\b.*\s-(delete|exec|…)\b/` — bypassed by `'-exec'`, `"-exec"`, `-''exec`, `-e"x"ec`, `$'-exec'`. Documented by Microsoft as intended best-effort, confirmed in source against commit `cdfcb384`.
- Same pattern applies to `sed`, `rg`, `sort`, `date`, `git branch`, `git log --output`, `column`.
- Function shadowing (`cd() { rm -rf /; }; cd /tmp`) does NOT bypass — `(command)` query captures inside function bodies. Harness proves this negative in seconds.

## Output location

Drop harness in `vuln-review/<target>/poc/bypass.mjs`. Save the run output to `vuln-review/<target>/evidence/run-output.txt` as deterministic evidence for reports.
