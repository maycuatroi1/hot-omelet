"""
Installation utilities module.
Handles tool installation for different platforms.
"""

import os
import platform
import subprocess
import click

from .scanner_utils import tool_exists


BURPSUITE_VERSION = "2026.2.3"
BURPSUITE_DIR = os.path.expanduser("~/tools/burpsuite")
BURPSUITE_JAR = os.path.join(BURPSUITE_DIR, "burpsuite_pro.jar")
BURPSUITE_LAUNCHER = os.path.join(BURPSUITE_DIR, "burpsuite")
BURPSUITE_BIN_LINK = os.path.expanduser("~/bin/burpsuite")


def install_tools(burpsuite=False):
    system = platform.system().lower()

    if burpsuite:
        _install_burpsuite()
        return

    _install_rust(system)
    _install_rustscan(system)
    _install_go(system)
    _install_katana(system)
    _install_flaresolverr()


def _install_rust(system: str):
    """Install Rust and Cargo based on the operating system."""
    # Check if cargo is available in user's .cargo/bin or system-wide
    cargo_user_path = os.path.expanduser("~/.cargo/bin/cargo")
    if tool_exists("cargo") or os.path.exists(cargo_user_path):
        click.echo("Rust/Cargo already installed.")
        return

    click.echo("Installing Rust and Cargo...")
    installers = {
        "darwin": _install_rust_macos,
        "linux": _install_rust_linux,
        "windows": _install_rust_windows,
    }

    installer = installers.get(system)
    if installer:
        installer()
    else:
        click.echo(
            f"Automatic installation not supported for {system}. Please install Rust manually from https://rustup.rs"
        )


def _install_rust_macos():
    """Install Rust on macOS."""
    if tool_exists("brew"):
        subprocess.run(["brew", "install", "rust"], check=False)
    else:
        # Use rustup installer
        click.echo("Installing Rust via rustup...")
        subprocess.run(
            [
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "-sSf",
                "https://sh.rustup.rs",
                "|",
                "sh",
                "-s",
                "--",
                "-y",
            ],
            shell=True,
            check=False,
        )


def _install_rust_linux():
    """Install Rust on Linux."""
    # Use rustup installer (recommended way)
    click.echo("Installing Rust via rustup...")
    subprocess.run(
        [
            "curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-sSf",
            "https://sh.rustup.rs",
            "|",
            "sh",
            "-s",
            "--",
            "-y",
        ],
        shell=True,
        check=False,
    )


def _install_rust_windows():
    """Install Rust on Windows."""
    if tool_exists("choco"):
        subprocess.run(["choco", "install", "rust", "-y"], check=False)
    elif tool_exists("scoop"):
        subprocess.run(["scoop", "install", "rust"], check=False)
    else:
        click.echo("Please install Rust manually from https://rustup.rs")
        click.echo(
            "Or install Chocolatey from https://chocolatey.org or Scoop from https://scoop.sh"
        )


def _install_rustscan(system: str):
    """Install RustScan using cargo."""
    # Check if rustscan is available in user's .cargo/bin or system-wide
    rustscan_user_path = os.path.expanduser("~/.cargo/bin/rustscan")
    if tool_exists("rustscan") or os.path.exists(rustscan_user_path):
        click.echo("RustScan already installed.")
        return

    # Check if cargo is available
    cargo_user_path = os.path.expanduser("~/.cargo/bin/cargo")
    cargo_cmd = "cargo"
    if os.path.exists(cargo_user_path):
        cargo_cmd = cargo_user_path
    elif not tool_exists("cargo"):
        click.echo("Cargo is required to install RustScan. Please install Rust first.")
        return

    click.echo("Installing RustScan...")
    subprocess.run([cargo_cmd, "install", "rustscan"], check=False)

    # Add .cargo/bin to PATH reminder
    rustscan_path = os.path.expanduser("~/.cargo/bin/rustscan")
    if os.path.exists(rustscan_path):
        click.echo("RustScan installed successfully.")
        click.echo(
            "Make sure ~/.cargo/bin is in your PATH to use 'rustscan' command directly."
        )
        if system == "windows":
            click.echo("On Windows, add %USERPROFILE%\\.cargo\\bin to your PATH.")
        else:
            click.echo(
                'You can add it by running: export PATH="$HOME/.cargo/bin:$PATH"'
            )
            click.echo(
                "Add the above line to your shell profile (~/.bashrc, ~/.zshrc, etc.) to make it permanent."
            )


def _install_go(system: str):
    """Install Go based on the operating system."""
    if tool_exists("go"):
        click.echo("Go already installed.")
        return

    click.echo("Installing Go...")
    installers = {
        "darwin": _install_go_macos,
        "linux": _install_go_linux,
        "windows": _install_go_windows,
    }

    installer = installers.get(system)
    if installer:
        installer()
    else:
        click.echo(
            f"Automatic installation not supported for {system}. Please install Go manually."
        )


def _install_go_macos():
    """Install Go on macOS."""
    if tool_exists("brew"):
        subprocess.run(["brew", "install", "go"], check=False)
    else:
        click.echo(
            "Homebrew is required to install Go on macOS. Install it from https://brew.sh"
        )


def _install_go_linux():
    """Install Go on Linux."""
    subprocess.run(["sudo", "apt-get", "update"], check=False)
    subprocess.run(["sudo", "apt-get", "install", "-y", "golang-go"], check=False)

    if not tool_exists("go"):
        click.echo("Failed to install Go via apt-get. Trying snap...")
        subprocess.run(["sudo", "snap", "install", "go", "--classic"], check=False)


def _install_go_windows():
    """Install Go on Windows."""
    if tool_exists("choco"):
        subprocess.run(["choco", "install", "golang", "-y"], check=False)
    elif tool_exists("scoop"):
        subprocess.run(["scoop", "install", "go"], check=False)
    else:
        click.echo("Chocolatey or Scoop is required to install Go on Windows.")
        click.echo(
            "Install Chocolatey from https://chocolatey.org or Scoop from https://scoop.sh"
        )


def _install_katana(system: str):
    """Install katana web crawler."""
    if tool_exists("katana"):
        click.echo("katana already installed.")
        return

    if not tool_exists("go"):
        click.echo("Go is required to install katana automatically.")
        return

    click.echo("Installing katana...")
    subprocess.run(
        ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
        check=False,
    )

    # Move katana to system path
    gopath = subprocess.run(
        ["go", "env", "GOPATH"], capture_output=True, text=True
    ).stdout.strip()

    katana_path = os.path.join(gopath, "bin", "katana")

    if os.path.exists(katana_path):
        if system == "darwin":  # macOS doesn't need sudo for /usr/local/bin
            subprocess.run(["mv", katana_path, "/usr/local/bin/"], check=False)
        elif system == "windows":
            # On Windows, the Go bin directory should already be in PATH
            click.echo("katana installed. Make sure %GOPATH%\\bin is in your PATH.")
        else:
            subprocess.run(["sudo", "mv", katana_path, "/usr/local/bin/"], check=False)


def _install_flaresolverr():
    if not tool_exists("docker"):
        click.echo("Docker is required to install FlareSolverr. Please install Docker first.")
        return

    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=flaresolverr", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    if "flaresolverr" in result.stdout:
        click.echo("FlareSolverr container already exists.")
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "flaresolverr"],
            capture_output=True, text=True,
        )
        if "true" not in state.stdout:
            click.echo("Starting FlareSolverr container...")
            subprocess.run(["docker", "start", "flaresolverr"], check=False)
        else:
            click.echo("FlareSolverr is already running on port 8191.")
        return

    click.echo("Installing FlareSolverr via Docker...")
    subprocess.run([
        "docker", "run", "-d",
        "--name", "flaresolverr",
        "-p", "8191:8191",
        "--restart", "unless-stopped",
        "ghcr.io/flaresolverr/flaresolverr:latest",
    ], check=False)
    click.echo("FlareSolverr installed and running on http://localhost:8191")


def _install_burpsuite():
    if os.path.exists(BURPSUITE_JAR):
        result = subprocess.run(
            ["java", "-jar", BURPSUITE_JAR, "--version"],
            capture_output=True, text=True, timeout=15,
        )
        version = result.stdout.strip()
        click.echo(f"Burp Suite already installed: {version}")
        click.echo(f"JAR: {BURPSUITE_JAR}")
        return

    if not tool_exists("java"):
        click.echo("[!] Java is required. Install with: sudo apt install default-jdk")
        return

    os.makedirs(BURPSUITE_DIR, exist_ok=True)

    download_url = (
        f"https://portswigger.net/burp/releases/startdownload"
        f"?product=pro&version={BURPSUITE_VERSION}&type=jar"
    )

    click.echo(f"Downloading Burp Suite Professional v{BURPSUITE_VERSION}...")
    click.echo("This is ~630MB, please wait...")

    result = subprocess.run(
        ["curl", "-L", download_url, "-o", BURPSUITE_JAR, "--progress-bar"],
        check=False,
    )

    if result.returncode != 0 or not os.path.exists(BURPSUITE_JAR):
        click.echo("[!] Download failed.")
        return

    size_mb = os.path.getsize(BURPSUITE_JAR) / (1024 * 1024)
    if size_mb < 100:
        click.echo(f"[!] Downloaded file too small ({size_mb:.0f}MB). Likely not the JAR.")
        os.remove(BURPSUITE_JAR)
        return

    with open(BURPSUITE_LAUNCHER, "w") as f:
        f.write(f"#!/bin/bash\njava -jar {BURPSUITE_JAR} \"$@\"\n")
    os.chmod(BURPSUITE_LAUNCHER, 0o755)

    bin_dir = os.path.expanduser("~/bin")
    os.makedirs(bin_dir, exist_ok=True)
    if os.path.exists(BURPSUITE_BIN_LINK):
        os.remove(BURPSUITE_BIN_LINK)
    os.symlink(BURPSUITE_LAUNCHER, BURPSUITE_BIN_LINK)

    bashrc = os.path.expanduser("~/.bashrc")
    path_line = 'export PATH="$HOME/bin:$PATH"'
    try:
        with open(bashrc) as f:
            content = f.read()
        if path_line not in content:
            with open(bashrc, "a") as f:
                f.write(f"\n{path_line}\n")
    except FileNotFoundError:
        pass

    if not tool_exists("xvfb-run"):
        click.echo("Installing xvfb for headless mode...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "xvfb"], check=False)

    click.echo(f"\nBurp Suite Professional v{BURPSUITE_VERSION} installed!")
    click.echo(f"  JAR:      {BURPSUITE_JAR}")
    click.echo(f"  Launcher: {BURPSUITE_LAUNCHER}")
    click.echo("  Command:  burpsuite (or ~/bin/burpsuite)")
    click.echo("\nFirst run: open GUI to activate license:")
    click.echo("  DISPLAY=:0 burpsuite")
    click.echo("\nHeadless scan after activation:")
    click.echo("  burpsuite --project-file=/tmp/project.burp --user-config-file=config.json")
