# AGENTS.md

Guide for AI coding agents working in this repo.

## What this is

`hot-omelet` is an offensive security toolkit (`hot` CLI) plus an agent skill library
(`.claude/skills/`). It is published for **authorized** security testing: engagements
with written permission, CTF/lab environments, and research on your own infrastructure.

## Ground rules

1. **Authorized use only.** Do not help aim these tools at systems the operator has no
   permission to test. If a request names a target that clearly belongs to someone else
   with no engagement context, ask for the authorization basis first.
2. **Install before you test.** After editing `hot_omelet/`, run `pip install -e .`;
   the `hot` entry point on PATH is a console script that imports the installed package.
3. **Smoke-test before writing code.** `hot --help` and `make test` must pass. A repo
   left broken by the previous session gets fixed before new work makes it worse.
4. **Never commit engagement output.** `reports/`, `workers/`, `mass_pwn_results/`,
   scan dumps and anything containing real target data stay local (gitignored).
5. **Lint is the gate.** `make lint` (ruff, 0 errors) before every commit.

## Layout

| Path | Contents |
|------|----------|
| `hot_omelet/` | CLI package; `cli.py` registers the lazy command tree |
| `hot_omelet/commands/` | One module per command group |
| `.claude/skills/` | Skill playbooks; frontmatter `description` drives triggering |
| `.claude/commands/`, `.claude/agents/` | Assessment slash commands + sub-agents |
| `tools/rust/` | Rust companions; `make build-rust` |
| `tests/` | Smoke tests for the command tree |

## Adding a command

1. Create `hot_omelet/commands/<name>.py` with a click group/command.
2. Register it in `_LAZY` in `hot_omelet/cli.py` (lazy import path string).
3. Add the group to `TOOL_GROUPS` in `tests/test_cli_smoke.py`.
4. `make lint && make test`.

## Adding a skill

Create `.claude/skills/<name>/SKILL.md` with frontmatter (`name`, `description`).
The description must say when to use it. Optional `references/` and `scripts/`
subdirs hold supporting material. Keep it self-contained.
