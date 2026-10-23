"""`hot github ...` - GitHub repo intelligence for white-box recon.

`github secrets` mines a public repo's file tree for hardcoded API keys, tokens,
and committed config before you touch the live backend. Backs the
`github-public-repo-secret-mining` skill.
"""
import json
import re

import click

from hot_omelet.commands._common import output_option, workers_option

_API = "https://api.github.com"
_RAW = "https://raw.githubusercontent.com"

# High-signal secret shapes (whole-match regexes).
_SECRET_RE = re.compile(
    r"AIza[A-Za-z0-9_-]{33}"
    r"|sk-or-v1-[A-Za-z0-9]{32,}"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r"|gsk_[A-Za-z0-9]{32,}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|pk_(?:live|test)_[A-Za-z0-9]{20,}"
    r"|mongodb(?:\+srv)?://[^\s\"'<>]+"
    r"|eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"
)
# Filenames that most often carry hardcoded secrets / leaked config.
_RISKY_RE = re.compile(
    r"(?:^|/)(?:test_|_test\.|\.env|config|secret|credential|api_?token|data/)"
    r"|\.(?:env|pem|key|json|js|py|ts)$",
    re.I,
)
_IMG_RE = re.compile(r"\.(png|jpe?g)$", re.I)


@click.group("github")
def github():
    """GitHub repo intelligence (white-box recon)."""


@github.command("secrets")
@click.argument("repo")  # owner/repo
@click.option("--branch", "-b", default="main", show_default=True,
              help="Branch to enumerate (falls back to master)")
@click.option("--token", "-t", envvar="GITHUB_TOKEN",
              help="GitHub token to raise the rate limit (env: GITHUB_TOKEN)")
@click.option("--max-files", default=300, show_default=True,
              help="Cap on candidate files to download+grep")
@workers_option(10)
@output_option()
def secrets(repo, branch, token, max_files, workers, output):
    """Mine hardcoded secrets & config from a public GitHub REPO (owner/repo)."""
    from concurrent.futures import ThreadPoolExecutor

    import requests
    from rich.console import Console
    from rich.table import Table

    console = Console()
    if repo.count("/") != 1:
        console.print("[red]REPO must be in owner/repo form[/red]")
        raise SystemExit(1)

    sess = requests.Session()
    sess.headers["Accept"] = "application/vnd.github+json"
    sess.headers["User-Agent"] = "hot-omelet"
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"

    # 1. repo metadata / visibility
    meta = sess.get(f"{_API}/repos/{repo}", timeout=15)
    if meta.status_code == 404:
        console.print(f"[red]repo {repo} not found (or private)[/red]")
        raise SystemExit(1)
    meta.raise_for_status()
    mj = meta.json()
    default_branch = mj.get("default_branch", branch)
    console.print(f"[bold]{repo}[/bold]  private={mj.get('private')}  "
                  f"default_branch=[cyan]{default_branch}[/cyan]")

    # 2. full file tree (try requested branch, then default)
    tree, used_branch = None, None
    for b in [branch, default_branch]:
        t = sess.get(f"{_API}/repos/{repo}/git/trees/{b}?recursive=1", timeout=20)
        if t.status_code == 200:
            tree, used_branch = t.json().get("tree", []), b
            break
    if not tree:
        console.print("[red]could not fetch file tree[/red]")
        raise SystemExit(1)

    files = [n["path"] for n in tree if n.get("type") == "blob"]
    candidates = [p for p in files if _RISKY_RE.search(p)][:max_files]
    images = [p for p in files if _IMG_RE.search(p) and
              re.search(r"api|key|token|secret|cred", p, re.I)]
    console.print(f"tree: [bold]{len(files)}[/bold] files, "
                  f"[yellow]{len(candidates)}[/yellow] risky candidates, "
                  f"[magenta]{len(images)}[/magenta] key-named images")

    # 3. download + grep candidates
    def scan(path):
        try:
            r = sess.get(f"{_RAW}/{repo}/{used_branch}/{path}", timeout=15)
            if r.status_code != 200 or len(r.content) > 2_000_000:
                return None
            hits = sorted({m.group(0) for m in _SECRET_RE.finditer(r.text)})
            return (path, hits) if hits else None
        except requests.RequestException:
            return None

    findings = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(scan, candidates):
            if res:
                findings.append(res)

    if findings:
        table = Table(title=f"Hardcoded secrets in {repo}")
        table.add_column("File", style="cyan")
        table.add_column("Secret(s)", style="red")
        for path, hits in findings:
            table.add_row(path, "\n".join(hits))
        console.print(table)
    else:
        console.print("[green]No high-signal secrets in scanned files.[/green]")

    if images:
        console.print("\n[bold magenta]Key-named images to inspect manually (OCR):[/bold magenta]")
        for p in images:
            console.print(f"  {_RAW}/{repo}/{used_branch}/{p}")

    console.print(f"\n[bold]{len(findings)}[/bold] file(s) with secrets. "
                  "[dim]Verify live before assuming compromise.[/dim]")

    if output:
        with open(output, "w") as f:
            json.dump({"repo": repo, "branch": used_branch,
                       "findings": [{"file": p, "secrets": h} for p, h in findings],
                       "images": images}, f, indent=2)
        console.print(f"[dim]-> {output}[/dim]")
