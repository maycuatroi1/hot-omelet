"""Smoke tests for the `hot` CLI tree.

Uses click's CliRunner so no external tools (nmap, scapy, ...) are needed -
we only assert that `--help` loads the command tree and every lazy group
resolves without import errors.
"""
from click.testing import CliRunner

from hot_omelet.cli import main
from hot_omelet.commands._common import LazyGroup


def test_main_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Hot Omelet" in result.output


def test_lazy_groups_resolve():
    """Every lazy group listed in _LAZY must resolve to a click command."""
    runner = CliRunner()
    main_cmd = main
    assert isinstance(main_cmd, LazyGroup)
    lazy = main_cmd._lazy
    ctx = main_cmd.make_context("hot", [], resilient_parsing=True)
    for name in lazy:
        cmd = main_cmd.get_command(ctx, name)
        assert cmd is not None, f"lazy command {name!r} did not resolve"


TOOL_GROUPS = [
    "redis", "mongo", "pgsql", "airflow", "minio", "supabase",
    "camera", "ssrf", "web", "github", "net", "cf",
    "dns", "beam", "dos",
]


def test_group_help(name=None):
    runner = CliRunner()
    failures = []
    for g in TOOL_GROUPS:
        r = runner.invoke(main, [g, "--help"])
        if r.exit_code != 0:
            failures.append((g, r.exit_code, r.output[:200]))
    assert not failures, f"group --help failures: {failures}"


def test_net_link_subcommands_help():
    """The new link-* subcommands must be registered under `hot net`."""
    runner = CliRunner()
    for sub in ["link-check", "link-setup", "link-discover", "link-sweep"]:
        r = runner.invoke(main, ["net", sub, "--help"])
        assert r.exit_code == 0, f"hot net {sub} --help failed: {r.output[:200]}"
