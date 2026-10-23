"""`hot camera ...` - IP camera / DVR / NVR discovery."""
import click


@click.group("camera")
def camera():
    """IP camera / DVR / NVR discovery and assessment."""


@camera.command("scan")
@click.argument("target", required=False)
@click.option("--rtsp/--no-rtsp", default=True, help="Verify RTSP streams via DESCRIBE (default on)")
@click.option("--creds/--no-creds", default=True, help="Test default credentials + CVE detection (default on)")
@click.option("--json", "json_out", help="Write structured findings to JSON")
def camera_scan(target, rtsp, creds, json_out):
    """Discover and assess IP cameras / DVRs / NVRs on a network.

    \b
    Examples:
      hot camera scan 192.168.1.0/24        # sweep + per-camera assessment
      hot camera scan 192.168.1.241         # single host
      hot camera scan 192.168.1.0/24 --no-creds --json cams.json
    """
    from hot_omelet.camera import camera_scan_command
    if not target:
        target = click.prompt("Enter target (IP or CIDR)", type=str)
    camera_scan_command(target, rtsp=rtsp, creds=creds, json_out=json_out)
