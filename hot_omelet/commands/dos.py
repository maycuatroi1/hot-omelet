"""`hot dos ...` - DoS exposure assessment and owned-infrastructure stress testing."""
import click


@click.group("dos")
def dos():
    """DoS exposure assessment (bounded probes) + stress testing (owned infra)."""


@dos.command("assess")
@click.argument("target")
@click.option("--probes", help="Comma-separated subset (default: all). "
              "Available: http2,slowloris,rudy,auth,ratelimit,workers,lockout,reset")
@click.option("--login-url", help="Auth endpoint to measure "
              "(default {target}/login/token.php)")
@click.option("--reset-url", help="Password-reset endpoint "
              "(default {target}/login/forgot_password.php)")
@click.option("--valid-user", help="A known-valid username (enables auth/lockout/reset probes)")
@click.option("--timeout", default=15.0, show_default=True, type=float, help="Per-request timeout (s)")
@click.option("--slow-deadline", default=40.0, show_default=True, type=float,
              help="Max seconds to hold slowloris/rudy connections (s)")
@click.option("--rate-requests", default=10, show_default=True, type=int,
              help="Requests for the rate-limit probe")
@click.option("--burst", default=20, show_default=True, type=int,
              help="Parallel requests for the worker-pool probe")
@click.option("--lockout-requests", default=5, show_default=True, type=int,
              help="Failures for the lockout probe")
@click.option("--send-reset/--no-send-reset", default=False,
              help="Also POST one password-reset request (queues one email)")
@click.option("--json", "json_out", help="Write structured findings to JSON")
def dos_assess(target, probes, login_url, reset_url, valid_user, timeout,
               slow_deadline, rate_requests, burst, lockout_requests,
               send_reset, json_out):
    """Measure DoS exposure with bounded, polite probes.

    \b
    Examples:
      hot dos assess elearning.example.edu.vn
      hot dos assess example.com --valid-user admin
      hot dos assess example.com --probes http2,slowloris --json dos.json
    """
    from hot_omelet.dos import dos_assess_command
    dos_assess_command(target, probes, login_url, reset_url, valid_user,
                       timeout, slow_deadline, rate_requests, burst,
                       lockout_requests, send_reset, json_out)


@dos.command("stress")
@click.argument("target")
@click.option("--mode", type=click.Choice(["auth", "http"]), default="http",
              show_default=True, help="auth = hash-verify flood on login endpoint; http = GET flood")
@click.option("--workers", default=8, show_default=True, type=int,
              help="Parallel workers (hard cap 256)")
@click.option("--duration", default=15.0, show_default=True, type=float,
              help="Seconds to run (hard cap 300)")
@click.option("--interval", default=0.0, show_default=True, type=float,
              help="Sleep between requests per worker (0 = as fast as possible)")
@click.option("--login-url", help="Auth endpoint for mode=auth "
              "(default {target}/login/token.php)")
@click.option("--valid-user", default="admin", show_default=True,
              help="Username used by mode=auth")
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--yes", is_flag=True, help="Skip the interactive confirmation "
              "(CI use - you must still be authorized)")
def dos_stress(target, mode, workers, duration, interval, login_url,
               valid_user, timeout, yes):
    """Load-test infrastructure you OWN. Generates real load; can take the target down.

    \b
    Examples:
      hot dos stress staging.example.com --workers 16 --duration 30
      hot dos stress staging.example.com --mode auth --valid-user admin --yes
    """
    from hot_omelet.dos import dos_stress_command
    dos_stress_command(target, mode, workers, duration, interval, login_url,
                       valid_user, timeout, yes)
