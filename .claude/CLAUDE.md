# Hot Omelet

Offensive security toolkit for **authorized** penetration testing and security research.
Everything here assumes the operator has permission for the targets being tested.

## Project layout

- `hot_omelet/` - the `hot` CLI (lazy-loaded click command tree)
- `hot_omelet/commands/` - one module per command group
- `.claude/skills/` - agent skill playbooks (plain Markdown, harness-agnostic)
- `.claude/commands/`, `.claude/agents/` - slash commands + sub-agents for assessments
- `tools/rust/` - hot-beam, hot-bf companions (`make build-rust`)
- `tests/` - pytest smoke tests; run with `make test`

## Working rules

- Install after editing: `pip install -e .` keeps the `hot` entry point current.
- Artifacts (scan output, reports, wordlists for a target) go under `./reports/` and
  `./workers/`. Both are gitignored - they are engagement output and never get committed.
- `make lint` (ruff) must pass with 0 errors before committing.
- Keep skills self-contained: a SKILL.md plus optional `references/` and `scripts/`.
- Function names, variables and code comments stay in English.

## CLI map

Run `hot --help` for the live tree. Top-level groups: `scan`, `assess`, `attack`,
`mass-pwn`, `redis`, `mongo`, `pgsql`, `airflow`, `minio`, `supabase`, `camera`,
`ssrf`, `dos`, `web`, `github`, `net`, `cf`, `dns`, `beam`, `wordlist`, `bf`,
`apk`, `censys`, `proxy`, `0-day`, `install`.
