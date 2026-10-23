"""APK Downloader - Download APKs from Google Play Store and APKPure."""

import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests
from rich import print


OAUTH_URL = "https://accounts.google.com/embedded/setup/v2/android?source=com.android.vending&xoauth_display_name=Android+Login&lang=en&langCountry=en_US&hl=en-US&cc=US"
ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")


def extract_package_id(input_str: str) -> str:
    """Extract package ID from a Play Store URL or raw package name."""
    input_str = input_str.strip()
    if "play.google.com" in input_str:
        parsed = urlparse(input_str)
        params = parse_qs(parsed.query)
        if "id" in params:
            return params["id"][0]
        # Try path-based format
        match = re.search(r"/store/apps/details\?id=([a-zA-Z0-9_.]+)", input_str)
        if match:
            return match.group(1)
        raise ValueError(f"Could not extract package ID from URL: {input_str}")
    # Validate as package name
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", input_str):
        return input_str
    raise ValueError(f"Invalid package ID or URL: {input_str}")


def ensure_apkeep() -> str:
    """Check if apkeep is installed, install via cargo if not. Returns path."""
    path = shutil.which("apkeep")
    if path:
        return path
    # Check common cargo bin location
    cargo_bin = os.path.expanduser("~/.cargo/bin/apkeep")
    if os.path.isfile(cargo_bin):
        return cargo_bin
    print("[yellow]apkeep not found. Installing via cargo...[/yellow]")
    if not shutil.which("cargo"):
        print("[red]cargo (Rust) not installed. Install from https://rustup.rs/[/red]")
        raise SystemExit(1)
    result = subprocess.run(
        ["cargo", "install", "apkeep"],
        capture_output=False,
    )
    if result.returncode != 0:
        print("[red]Failed to install apkeep[/red]")
        raise SystemExit(1)
    if os.path.isfile(cargo_bin):
        return cargo_bin
    final = shutil.which("apkeep")
    if final:
        return final
    print("[red]apkeep installed but not found in PATH[/red]")
    raise SystemExit(1)


def _load_env() -> dict[str, str]:
    """Load .env file as dict."""
    env = {}
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    env[key.strip()] = value.strip()
    return env


def _save_env_vars(updates: dict[str, str]):
    """Update or append variables in .env file."""
    lines = []
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE) as f:
            lines = f.readlines()

    updated_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}\n")
                updated_keys.add(key)
                continue
        new_lines.append(line)

    # Append new keys
    for key, value in updates.items():
        if key not in updated_keys:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{key}={value}\n")

    with open(ENV_FILE, "w") as f:
        f.writelines(new_lines)


def _launch_login_browser(p):
    """Launch a headed Chromium for the Google login flow.

    Prefer the system-installed Google Chrome (``channel="chrome"``) because the
    Playwright-bundled Chromium is unsigned and the very first launch after a
    fresh ``playwright install`` is frequently killed by Gatekeeper on recent
    macOS with a BUS_ADRALN bus error. Fall back to the bundled build when no
    system Chrome is available.
    """
    args = ["--disable-blink-features=AutomationControlled"]
    try:
        browser = p.chromium.launch(headless=False, channel="chrome", args=args)
        print("[dim]  Using system Google Chrome[/dim]")
        return browser
    except Exception as e:
        print(f"[dim]  System Chrome unavailable ({str(e).splitlines()[0]}), using bundled Chromium[/dim]")
        return p.chromium.launch(headless=False, args=args)


def _get_oauth_token_playwright(email: str, password: str) -> str | None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[red]playwright not installed. Run: pip install playwright && playwright install chromium[/red]")
        return None

    print("[cyan]Launching browser for Google login...[/cyan]")
    try:
        with sync_playwright() as p:
            browser = _launch_login_browser(p)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                locale="en-US",
                viewport={"width": 1280, "height": 720},
            )
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            page = context.new_page()
            page.goto(OAUTH_URL)
            page.wait_for_timeout(2000)

            print("[dim]  Entering email...[/dim]")
            page.get_by_role("textbox", name="Email or phone").fill(email)
            page.locator("#identifierNext button").click()

            print("[dim]  Entering password...[/dim]")
            pwd_field = page.get_by_role("textbox", name="Enter your password")
            pwd_field.wait_for(state="visible", timeout=10000)
            pwd_field.press_sequentially(password)
            page.locator("#passwordNext button").click()
            page.wait_for_timeout(4000)

            if "Wrong password" in page.content():
                print("[red]Wrong password![/red]")
                browser.close()
                return None

            print("[dim]  Accepting Terms of Service...[/dim]")
            try:
                agree_btn = page.get_by_role("button", name="I agree")
                agree_btn.wait_for(state="visible", timeout=10000)
                agree_btn.click()
            except Exception:
                pass

            for _ in range(10):
                page.wait_for_timeout(1000)
                cookies = context.cookies()
                oauth = next((c for c in cookies if c["name"] == "oauth_token"), None)
                if oauth:
                    break

            browser.close()

            if oauth:
                print("[green]  OAuth token obtained![/green]")
                return oauth["value"]
            print("[red]  Could not find oauth_token cookie[/red]")
            return None
    except Exception as e:
        print(f"[red]  Playwright error: {e}[/red]")
        return None


def _exchange_oauth_for_aas(email: str, oauth_token: str) -> str | None:
    url = "https://android.clients.google.com/auth"
    data = {
        "lang": "en_US",
        "google_play_services_version": "242913038",
        "sdk_version": "28",
        "device_country": "us",
        "Email": email,
        "service": "ac2dm",
        "get_accountid": "1",
        "ACCESS_TOKEN": "1",
        "callerPkg": "com.google.android.gms",
        "add_account": "1",
        "Token": oauth_token,
        "callerSig": "38918a453d07199354f8b19af05ec6562ced5788",
        "client_sig": "38918a453d07199354f8b19af05ec6562ced5788",
        "droidguard_results": "CgYxMjM0NTYKAA",
        "has_permission": "1",
        "source": "android",
        "androidId": "0000000000000000",
        "app": "com.google.android.gms",
        "check_email": "1",
        "token_request_options": "CAA4AVAB",
        "system_partition": "1",
    }
    headers = {
        "app": "com.google.android.gms",
        "device": "0000000000000000",
        "User-Agent": "GoogleAuth/1.4 (Pixel 3a XL PQ3A.190801.002); gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
    }
    resp = requests.post(url, data=data, headers=headers, timeout=15)
    if resp.status_code != 200:
        return None
    for line in resp.text.splitlines():
        if line.startswith("Token="):
            return line.split("=", 1)[1]
    return None


def setup_google_account(email: str | None = None, oauth_token: str | None = None) -> tuple[str, str]:
    ensure_apkeep()

    if not email:
        email = input("Enter Google email: ").strip()

    password = None
    aas_token = None

    if not oauth_token:
        password = input("Enter Google password: ").strip()
        if not password:
            print("[red]No password provided[/red]")
            raise SystemExit(1)

        print("\n[cyan]Automated OAuth flow (Playwright)...[/cyan]")
        oauth_token = _get_oauth_token_playwright(email, password)

    if oauth_token:
        print("[cyan]Converting OAuth token to AAS token...[/cyan]")
        aas_token = _exchange_oauth_for_aas(email, oauth_token)

    if not aas_token and oauth_token:
        print("[yellow]Direct API exchange failed, trying manual fallback...[/yellow]")
        print(f"[dim]OAuth token: {oauth_token[:30]}...[/dim]")
        aas_token = input("\nPaste AAS token manually (if you have one): ").strip() or None

    if not aas_token and not oauth_token:
        print("\n[yellow]Automated flow failed. Falling back to manual setup...[/yellow]")
        print(f"\n[cyan]Step 1:[/cyan] Open this URL in browser and login with [yellow]{email}[/yellow]:")
        print(f"[link]{OAUTH_URL}[/link]\n")
        print("[cyan]Step 2:[/cyan] After login, open browser DevTools (F12) → Console, run:")
        print('[yellow]cookieStore.get("oauth_token").then(c => console.log(c.value))[/yellow]\n')
        oauth_token = input("Paste OAuth token: ").strip()
        if oauth_token:
            aas_token = _exchange_oauth_for_aas(email, oauth_token)
        if not aas_token:
            aas_token = input("\nPaste AAS token manually: ").strip() or None

    if not aas_token:
        print("[red]No AAS token obtained[/red]")
        raise SystemExit(1)

    _save_env_vars({
        "GOOGLE_EMAIL": email,
        "GOOGLE_AAS_TOKEN": aas_token,
    })
    print(f"\n[green]Setup complete! Saved to {ENV_FILE}[/green]")
    print(f"  Email: [yellow]{email}[/yellow]")
    print(f"  AAS Token: [yellow]{aas_token[:20]}...[/yellow]")
    return email, aas_token


def download_apk(
    package_id: str,
    source: str = "google-play",
    output_dir: str = ".",
    email: str | None = None,
    aas_token: str | None = None,
) -> str | None:
    """Download APK using apkeep. Returns path to downloaded file."""
    if source == "apk-pure":
        return download_from_apkpure(package_id, output_dir)

    # Google Play download
    if not email or not aas_token:
        env = _load_env()
        email = email or env.get("GOOGLE_EMAIL")
        aas_token = aas_token or env.get("GOOGLE_AAS_TOKEN")

    if not email or not aas_token:
        print("[red]Google account not configured. Run: hot apk --setup[/red]")
        return None

    apkeep = ensure_apkeep()
    os.makedirs(output_dir, exist_ok=True)

    print(f"[cyan]Downloading [yellow]{package_id}[/yellow] from Google Play...[/cyan]")
    result = subprocess.run(
        [apkeep, "-a", package_id, "-d", "google-play",
         "-e", email, "-t", aas_token, output_dir],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"[red]Download failed:[/red]\n{result.stderr or result.stdout}")
        return None

    # Find downloaded file(s)
    downloaded = _find_downloaded_files(output_dir, package_id)
    if downloaded:
        for f in downloaded:
            size_mb = os.path.getsize(f) / (1024 * 1024)
            print(f"[green]Downloaded:[/green] {f} ({size_mb:.1f} MB)")
        return downloaded[0]

    print(f"[yellow]apkeep output:[/yellow]\n{result.stdout}")
    if result.stderr:
        print(f"[dim]{result.stderr}[/dim]")
    return None


def download_from_apkpure(package_id: str, output_dir: str = ".") -> str | None:
    """Download APK from APKPure (no auth required)."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"[cyan]Downloading [yellow]{package_id}[/yellow] from APKPure...[/cyan]")

    # Get the APKPure download page
    url = f"https://apkpure.com/search?q={package_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        # Find direct app page link
        match = re.search(
            rf'href="(https://apkpure\.com/[^"]*/{re.escape(package_id)})"',
            resp.text,
        )
        if not match:
            # Try alternative pattern
            match = re.search(
                rf'href="(/[^"]*/{re.escape(package_id)})"',
                resp.text,
            )

        if not match:
            print("[red]App not found on APKPure[/red]")
            return None

        app_url = match.group(1)
        if not app_url.startswith("http"):
            app_url = f"https://apkpure.com{app_url}"

        # Get download page
        download_page_url = f"{app_url}/download"
        resp = requests.get(download_page_url, headers=headers, timeout=15)
        resp.raise_for_status()

        # Find APK download link
        dl_match = re.search(
            r'href="(https://d\.apkpure\.com/[^"]*\.apk[^"]*)"',
            resp.text,
        )
        if not dl_match:
            # Try alternative CDN pattern
            dl_match = re.search(
                r'href="(https://[^"]*\.apkpure\.[^"]*\.apk[^"]*)"',
                resp.text,
            )

        if not dl_match:
            # Fallback: use apkeep with apk-pure source
            apkeep = ensure_apkeep()
            result = subprocess.run(
                [apkeep, "-a", package_id, "-d", "apk-pure", output_dir],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                downloaded = _find_downloaded_files(output_dir, package_id)
                if downloaded:
                    for f in downloaded:
                        size_mb = os.path.getsize(f) / (1024 * 1024)
                        print(f"[green]Downloaded:[/green] {f} ({size_mb:.1f} MB)")
                    return downloaded[0]
            print("[red]Could not find download link on APKPure[/red]")
            if result.stdout:
                print(f"[dim]{result.stdout}[/dim]")
            return None

        dl_url = dl_match.group(1)
        output_path = os.path.join(output_dir, f"{package_id}.apk")

        print(f"[dim]Downloading from {dl_url[:80]}...[/dim]")
        dl_resp = requests.get(dl_url, headers=headers, stream=True, timeout=60)
        dl_resp.raise_for_status()

        total = int(dl_resp.headers.get("content-length", 0))
        downloaded_bytes = 0
        with open(output_path, "wb") as f:
            for chunk in dl_resp.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded_bytes += len(chunk)
                if total > 0:
                    pct = downloaded_bytes * 100 // total
                    print(f"\r[dim]Progress: {pct}% ({downloaded_bytes // 1024 // 1024}MB / {total // 1024 // 1024}MB)[/dim]", end="")
        print()

        size_mb = os.path.getsize(output_path) / (1024 * 1024)
        print(f"[green]Downloaded:[/green] {output_path} ({size_mb:.1f} MB)")
        return output_path

    except requests.RequestException as e:
        print(f"[red]APKPure download failed: {e}[/red]")
        # Fallback to apkeep apk-pure source
        print("[yellow]Trying apkeep with apk-pure source...[/yellow]")
        apkeep = ensure_apkeep()
        result = subprocess.run(
            [apkeep, "-a", package_id, "-d", "apk-pure", output_dir],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            downloaded = _find_downloaded_files(output_dir, package_id)
            if downloaded:
                for f in downloaded:
                    size_mb = os.path.getsize(f) / (1024 * 1024)
                    print(f"[green]Downloaded:[/green] {f} ({size_mb:.1f} MB)")
                return downloaded[0]
        print("[red]All download methods failed[/red]")
        return None


def list_versions(
    package_id: str,
    email: str | None = None,
    aas_token: str | None = None,
):
    """List available versions for a package."""
    if not email or not aas_token:
        env = _load_env()
        email = email or env.get("GOOGLE_EMAIL")
        aas_token = aas_token or env.get("GOOGLE_AAS_TOKEN")

    if not email or not aas_token:
        print("[red]Google account not configured. Run: hot apk --setup[/red]")
        return

    apkeep = ensure_apkeep()
    print(f"[cyan]Listing versions for [yellow]{package_id}[/yellow]...[/cyan]")

    result = subprocess.run(
        [apkeep, "-a", package_id, "-d", "google-play",
         "-e", email, "-t", aas_token, "--list-versions", "."],
        capture_output=True,
        text=True,
    )

    output = (result.stdout + "\n" + result.stderr).strip()
    if output:
        print(output)
    else:
        print("[yellow]No version info returned. The app may not be available in your region.[/yellow]")


def _find_downloaded_files(output_dir: str, package_id: str) -> list[str]:
    """Find recently downloaded APK/XAPK files matching the package ID."""
    results = []
    for f in Path(output_dir).iterdir():
        if f.is_file() and package_id in f.name and f.suffix in (".apk", ".xapk", ".apks"):
            results.append(str(f))
    # Also check subdirectory named after the package
    pkg_dir = Path(output_dir) / package_id
    if pkg_dir.is_dir():
        for f in pkg_dir.iterdir():
            if f.is_file() and f.suffix in (".apk", ".xapk", ".apks"):
                results.append(str(f))
    return sorted(results, key=os.path.getmtime, reverse=True)
