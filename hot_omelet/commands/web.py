"""`hot web ...` - web-application enumeration & exploitation.

Consolidates repeated recon patterns from prior engagements:
  * `web bundle`    - download + fingerprint SPA / Next.js JS bundles for
                      endpoints, backend URLs, BaaS config, and hardcoded secrets.
  * `web endpoints` - batch-probe a path list against a base URL (status/size/ct).
  * `web api`       - authenticated single request wrapper (Bearer) for IDOR/BOLA.

See the `spa-bundle-analysis`, `spa-authed-api-secret-disclosure`, and
`jwt-hs256-secret-crack` skills for the methodology behind these commands.
"""
import json
import re

import click

from hot_omelet.commands._common import output_option, timeout_option, workers_option

# --- shared regexes -------------------------------------------------------
_SECRET_RE = re.compile(
    r"AIza[A-Za-z0-9_-]{33}"                # Google API key
    r"|sk-or-v1-[A-Za-z0-9]{32,}"           # OpenRouter
    r"|sk-[A-Za-z0-9_-]{20,}"               # OpenAI-style
    r"|gsk_[A-Za-z0-9]{32,}"                # Groq
    r"|pk_(live|test)_[A-Za-z0-9]{20,}"     # Stripe publishable
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"        # Slack
    r"|eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"  # JWT
    r"|mongodb(\+srv)?://[^\s\"'<>]+"       # Mongo URI
)
_URL_RE = re.compile(r"https?://[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]+")
_ENV_RE = re.compile(r"(?:NEXT_PUBLIC_|VITE_)[A-Z0-9_]+")
_BAAS_RE = re.compile(
    r"firebase|supabase|railway\.app|onrender|herokuapp|amazonaws|googleapis|vercel",
    re.I,
)
_AUTH_RE = re.compile(
    r"Authorization|Bearer|X-API-Key|X-CSRF|X-XSRF-TOKEN|withCredentials", re.I
)

_PRESETS = {
    "auth": ["/api/auth/me", "/api/auth/login", "/api/users/me", "/api/settings/user",
             "/api/register", "/api/auth/sign-up/email", "/auth/v1/signup"],
    "actuator": ["/", "/health", "/api/health", "/actuator", "/actuator/health",
                 "/actuator/env", "/actuator/metrics", "/actuator/mappings",
                 "/actuator/configprops", "/actuator/beans"],
    "api": ["/api", "/api/users", "/api/settings", "/api/settings/system",
            "/api/llms", "/api/agents", "/api/integrations", "/api/connections",
            "/api/datasources"],
}
_PRESETS["all"] = sorted({p for v in _PRESETS.values() for p in v})


@click.group("web")
def web():
    """Web-app security enumeration & exploitation."""


# =========================================================================
# web bundle
# =========================================================================
@web.command("bundle")
@click.argument("url")
@click.option("--download-dir", "-o", default="/tmp/bundle-analysis",
              type=click.Path(), help="Where to save fetched JS")
@timeout_option(15)
@output_option("Write findings JSON to this file")
def bundle(url, download_dir, timeout, output):
    """Download + fingerprint a SPA / Next.js bundle for endpoints & secrets.

    Auto-detects Next.js (enumerates /_next/static chunks) vs a generic Vite/React
    SPA (grabs the main /assets/index-*.js). Greps every fetched chunk for URLs,
    BaaS config, hardcoded secrets, NEXT_PUBLIC_/VITE_ env vars, and auth headers.
    """
    import os

    import requests
    from rich.console import Console

    console = Console()
    os.makedirs(download_dir, exist_ok=True)
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0"

    def fetch(u):
        try:
            r = sess.get(u, timeout=timeout)
            return r.text if r.status_code == 200 else ""
        except requests.RequestException as e:
            console.print(f"[dim]fetch failed {u}: {e}[/dim]")
            return ""

    base = url.rstrip("/")
    console.print(f"[bold]Bundle analysis[/bold] -> [cyan]{base}[/cyan]")
    root = fetch(base + "/")

    chunk_urls = []
    build_id = None
    m = re.search(r"_next/static/([A-Za-z0-9_-]{8,})/", root)
    if m:
        build_id = m.group(1)
        console.print(f"[green]Next.js detected[/green] build_id=[cyan]{build_id}[/cyan]")
        manifest = fetch(f"{base}/_next/static/{build_id}/_buildManifest.js")
        for c in sorted(set(re.findall(r"static/chunks/[A-Za-z0-9._/-]+?\.js", manifest))):
            chunk_urls.append(f"{base}/_next/{c}" if not c.startswith("_next") else f"{base}/{c}")
        # also pull chunk refs straight out of the root HTML
        for c in sorted(set(re.findall(r"/_next/static/[A-Za-z0-9._/-]+?\.js", root))):
            chunk_urls.append(base + c)
    else:
        for c in sorted(set(re.findall(r"/assets/[A-Za-z0-9._-]+?\.js", root))):
            chunk_urls.append(base + c)
        for c in sorted(set(re.findall(r'src="([^"]+?\.js)"', root))):
            chunk_urls.append(c if c.startswith("http") else base + "/" + c.lstrip("/"))

    chunk_urls = sorted(set(chunk_urls))
    if not chunk_urls:
        console.print("[yellow]No JS chunks found in root HTML; "
                      "pass a direct bundle URL instead.[/yellow]")
        return

    console.print(f"Fetching [bold]{len(chunk_urls)}[/bold] chunk(s)...")
    blob = ""
    for cu in chunk_urls:
        blob += fetch(cu) + "\n"

    findings = {
        # _SECRET_RE contains groups, so use finditer + group(0) for whole matches
        "secrets": sorted({m.group(0) for m in _SECRET_RE.finditer(blob)}),
        "urls": sorted({u for u in _URL_RE.findall(blob)
                        if not u.startswith(base)})[:200],
        "env": sorted(set(_ENV_RE.findall(blob))),
        "baas": sorted(set(m.lower() for m in _BAAS_RE.findall(blob))),
        "auth": sorted(set(m for m in _AUTH_RE.findall(blob))),
        "chunks": chunk_urls,
        "build_id": build_id,
    }

    _print_bundle(console, findings)
    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        console.print(f"[dim]findings -> {output}[/dim]")


def _print_bundle(console, f):
    def section(title, items, style):
        if not items:
            return
        console.print(f"\n[bold {style}]{title}[/bold {style}] ({len(items)})")
        for it in items:
            console.print(f"  {it}")

    section("SECRETS", f["secrets"], "red")
    section("BaaS / cloud", f["baas"], "magenta")
    section("Env vars", f["env"], "yellow")
    section("Auth patterns", f["auth"], "cyan")
    section("External URLs", f["urls"], "green")
    if f["secrets"]:
        console.print("\n[bold red]! hardcoded secrets present - verify if live "
                      "before assuming compromise[/bold red]")


# =========================================================================
# web endpoints
# =========================================================================
@web.command("endpoints")
@click.argument("base_url")
@click.option("--preset", type=click.Choice(list(_PRESETS)), default="api",
              show_default=True, help="Built-in path set")
@click.option("--paths", type=click.File(), help="Wordlist: one path per line (overrides preset)")
@click.option("--auth", "auth_header", help="Bearer token (or full Authorization value)")
@click.option("--method", "-X", default="GET", show_default=True)
@workers_option(10)
@timeout_option(8)
@output_option()
def endpoints(base_url, preset, paths, auth_header, method, workers, timeout, output):
    """Batch-probe a path list against BASE_URL; report code / size / content-type."""
    from concurrent.futures import ThreadPoolExecutor

    import requests
    from rich.console import Console
    from rich.table import Table

    console = Console()
    base = base_url.rstrip("/")
    path_list = ([p.strip() for p in paths if p.strip()] if paths
                 else _PRESETS[preset])
    headers = {"User-Agent": "Mozilla/5.0"}
    if auth_header:
        headers["Authorization"] = (auth_header if auth_header.lower().startswith("bearer")
                                     else f"Bearer {auth_header}")

    def probe(path):
        u = base + (path if path.startswith("/") else "/" + path)
        try:
            r = requests.request(method, u, headers=headers, timeout=timeout,
                                 allow_redirects=False)
            return (path, r.status_code, len(r.content),
                    r.headers.get("content-type", "").split(";")[0])
        except requests.RequestException as e:
            return (path, "ERR", 0, str(e)[:30])

    console.print(f"[bold]Probing[/bold] {len(path_list)} path(s) -> [cyan]{base}[/cyan]"
                  + (" [dim](authed)[/dim]" if auth_header else ""))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = sorted(ex.map(probe, path_list), key=lambda r: str(r[1]))

    table = Table(title=f"Endpoint probe: {base}")
    table.add_column("Path", style="cyan", no_wrap=True)
    table.add_column("Code", justify="right")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Content-Type", style="green")
    for path, code, size, ct in results:
        color = {200: "green", 401: "yellow", 403: "yellow", 500: "red"}.get(code, "white")
        table.add_row(path, f"[{color}]{code}[/{color}]", str(size), ct)
    console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump([{"path": p, "code": c, "size": s, "content_type": ct}
                       for p, c, s, ct in results], f, indent=2)


# =========================================================================
# web api
# =========================================================================
@web.command("api")
@click.argument("url")
@click.option("--token", "-t", help="JWT / Bearer token")
@click.option("--method", "-X", default="GET", show_default=True,
              type=click.Choice(["GET", "POST", "PUT", "PATCH", "DELETE"]))
@click.option("--body", "-d", help="Request body (JSON string)")
@click.option("--header", "-H", multiple=True, help="Extra header 'K: V' (repeatable)")
@timeout_option(15)
def api(url, token, method, body, header, timeout):
    """Authenticated single request wrapper (for IDOR/BOLA replay)."""
    import requests
    from rich.console import Console
    from rich.syntax import Syntax

    console = Console()
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for h in header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    payload = None
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            console.print("[red]--body is not valid JSON[/red]")
            raise SystemExit(1)

    try:
        r = requests.request(method, url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as e:
        console.print(f"[red]request failed: {e}[/red]")
        raise SystemExit(1)

    color = "green" if r.ok else ("yellow" if r.status_code < 500 else "red")
    console.print(f"[bold {color}]{method} {url} -> {r.status_code}[/bold {color}]  "
                  f"[dim]{len(r.content)} bytes[/dim]")
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        try:
            pretty = json.dumps(r.json(), indent=2)
            console.print(Syntax(pretty, "json", theme="ansi_dark", word_wrap=True))
            # flag secret-shaped fields in the response
            leaks = sorted({m.group(0) for m in _SECRET_RE.finditer(pretty)})
            secret_keys = re.findall(
                r'"(apiKey|api_key|secret|token|password|connectionString|dsn|'
                r'privateKey|webhookSecret|clientSecret)"\s*:', pretty, re.I)
            if leaks or secret_keys:
                console.print("[bold red]! secret-shaped data in response:[/bold red] "
                              f"keys={sorted(set(secret_keys))} values={leaks}")
        except ValueError:
            console.print(r.text[:4000])
    else:
        console.print(r.text[:4000])
