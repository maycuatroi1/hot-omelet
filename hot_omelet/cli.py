"""Hot Omelet CLI entry point.

The command tree is registered through `LazyGroup` so that `hot --help` and
single-subcommand invocations only import the modules they actually need.
"""
import click

from hot_omelet.commands._common import LazyGroup


_LAZY = {
    # Top-level single-action commands
    "scan":      "hot_omelet.commands.tools:scan",
    "install":   "hot_omelet.commands.tools:install",
    "attack":    "hot_omelet.commands.tools:attack_cmd",
    "0-day":     "hot_omelet.commands.tools:zero_day_cmd",
    "assess":    "hot_omelet.commands.tools:assess_cmd",
    "wordlist":  "hot_omelet.commands.tools:wordlist_cmd",
    "bf":        "hot_omelet.commands.tools:bf_cmd",
    "apk":       "hot_omelet.commands.tools:apk_cmd",
    "censys":    "hot_omelet.commands.tools:censys_cmd",
    "proxy":     "hot_omelet.commands.tools:proxy_cmd",
    "setup-ssh": "hot_omelet.commands.tools:setup_ssh_cmd",
    "mass-pwn":  "hot_omelet.commands.tools:mass_pwn_cmd",

    # Service exploitation groups
    "redis":   "hot_omelet.commands.redis:redis",
    "mongo":   "hot_omelet.commands.mongo:mongo",
    "pgsql":   "hot_omelet.commands.pgsql:pgsql",
    "airflow": "hot_omelet.commands.airflow:airflow",
    "minio":   "hot_omelet.commands.minio:minio",
    "supabase": "hot_omelet.commands.supabase:supabase",
    "camera":  "hot_omelet.commands.camera:camera",
    "ssrf":    "hot_omelet.commands.ssrf:ssrf",
    "dos":     "hot_omelet.commands.dos:dos",

    # Web-app enumeration & exploitation
    "web":    "hot_omelet.commands.web:web",
    "github": "hot_omelet.commands.github:github",

    # Network groups
    "net": "hot_omelet.commands.net:net",
    "cf":  "hot_omelet.commands.cf:cf",
    "dns": "hot_omelet.commands.dns:dns",

    # Tooling groups
    "beam":  "hot_omelet.beam:beam_command",
}


class _HotGroup(LazyGroup):
    """`hot` with `scan` as the implicit default command."""

    def resolve_command(self, ctx, args):
        if args and args[0] not in self.list_commands(ctx) and not args[0].startswith("-"):
            args.insert(0, "scan")
        return super().resolve_command(ctx, args)


@click.command(cls=_HotGroup, lazy_subcommands=_LAZY, invoke_without_command=True)
@click.pass_context
def main(ctx):
    """Hot Omelet offensive security toolkit."""
    if ctx.invoked_subcommand is None:
        scan_cmd = ctx.command.get_command(ctx, "scan")
        ctx.invoke(scan_cmd, target=None, no_creds=False)


if __name__ == "__main__":
    main()
