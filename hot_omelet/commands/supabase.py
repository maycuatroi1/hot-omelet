"""`hot supabase ...` - Supabase RLS / anon-key audit."""
import click


@click.group("supabase")
def supabase():
    """Supabase RLS misconfiguration audit."""


@supabase.command("audit")
@click.argument("url", required=False, default="")
@click.argument("anon_key", required=False, default="")
@click.option("--from-bundle", help="Target URL to auto-extract Supabase URL + anon key from its JS bundle")
@click.option("--tables", help="Comma-separated table names to probe (default: built-in wordlist)")
@click.option("--dump", is_flag=True, help="Bulk-dump tables that leak PII/secrets into workers/<ref>/loot/")
@click.option("--output-dir", help="Directory for dumped loot (default: workers/<ref>/loot)")
@click.option("--timeout", default=12, show_default=True, type=int, help="Per-request timeout in seconds")
def supabase_audit(url, anon_key, from_bundle, tables, dump, output_dir, timeout):
    """Probe a Supabase project for over-permissive RLS using the anon key.

    Provide URL + ANON_KEY directly, or pass --from-bundle <target-url> to pull
    them out of the app's JS bundle automatically.
    """
    from hot_omelet.supabase_audit import supabase_audit_command
    if not from_bundle and (not url or not anon_key):
        raise click.UsageError("Provide URL and ANON_KEY, or use --from-bundle <target-url>.")
    supabase_audit_command(
        url=url or None,
        anon_key=anon_key or None,
        tables=[t.strip() for t in tables.split(",")] if tables else None,
        from_bundle=from_bundle,
        dump=dump,
        output_dir=output_dir,
        timeout=timeout,
    )
