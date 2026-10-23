"""Shahot CLI helpers: option decorators, prompt utilities, LazyGroup."""
from __future__ import annotations

import importlib
from typing import Callable

import click


def prompt_host(host: str | None, label: str = "hostname or IP") -> str:
    return host or click.prompt(f"Enter {label}", type=str)


def host_port_options(default_port: int, port_help: str = "Service port"):
    """Add `--host`/`--port` to a command."""
    def deco(f: Callable) -> Callable:
        f = click.option("--port", default=default_port, show_default=True, type=int, help=port_help)(f)
        f = click.option("--host", required=False, help="Target hostname or IP")(f)
        return f
    return deco


def workers_option(default: int = 10):
    return click.option("--workers", default=default, show_default=True, type=int,
                        help="Number of parallel workers")


def timeout_option(default: int = 5):
    return click.option("--timeout", default=default, show_default=True, type=int,
                        help="Connection timeout in seconds")


def output_option(help_text: str = "Output file for results (JSON)"):
    return click.option("--output", help=help_text)


class LazyGroup(click.Group):
    """Click group that resolves subcommands lazily from `module:attr` refs.

    Usage:
        main = LazyGroup(lazy_subcommands={
            "redis": "hot_omelet.commands.redis:redis",
            "scan":  "hot_omelet.commands.tools:scan",
        })

    The target attribute must be a `click.Command` or `click.Group`.
    """

    def __init__(self, *args, lazy_subcommands: dict[str, str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._lazy = lazy_subcommands or {}

    def list_commands(self, ctx):
        return sorted(set(self.commands) | set(self._lazy))

    def get_command(self, ctx, cmd_name):
        if cmd_name in self.commands:
            return self.commands[cmd_name]
        ref = self._lazy.get(cmd_name)
        if not ref:
            return None
        module_path, _, attr = ref.partition(":")
        if not attr:
            raise click.ClickException(f"Invalid lazy ref: {ref!r}")
        cmd = getattr(importlib.import_module(module_path), attr)
        if not isinstance(cmd, click.BaseCommand):
            raise click.ClickException(f"{ref!r} is not a click command")
        self.commands[cmd_name] = cmd
        return cmd
