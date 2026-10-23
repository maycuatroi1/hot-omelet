"""Hermetic tests for `hot dos` - probes run against a local threaded HTTP server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from hot_omelet.cli import main
from hot_omelet.dos.http_utils import normalize_url
from hot_omelet.dos.probes import findings_from_probes, probe_http2, probe_rudy, probe_slowloris


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 2

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        payload = json.dumps({"got": len(body)}).encode()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def local_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://a.b/") == "http://a.b"


def test_http2_probe_plain(local_server):
    res = probe_http2(local_server)
    assert res["ok"] and res["result"]["h2"] is False


def test_slowloris_probe_closes(local_server):
    """Local server answers immediately once the line is incomplete -> closes fast."""
    res = probe_slowloris(local_server, timeout=5.0)
    assert res["ok"]
    assert res["result"]["server_closed"] is True
    assert res["result"]["held_seconds"] < 5.0


def test_rudy_probe(local_server):
    res = probe_rudy(local_server, timeout=5.0)
    assert res["ok"]
    assert "server_closed" in res["result"]


def test_findings_from_http2():
    findings = findings_from_probes([{"probe": "http2", "result": {"h2": True, "alpn": "h2"}}])
    assert any(f["level"] == "HIGH" and f["service"] == "HTTP/2" for f in findings)


def test_findings_from_auth_delta():
    probes = [{"probe": "auth_cost", "result": {
        "cheap_seconds": 0.4, "hash_seconds": 0.9, "cpu_delta_seconds": 0.5}}]
    findings = findings_from_probes(probes)
    assert any(f["level"] == "HIGH" and f["vector"].startswith("CPU asymmetry") for f in findings)


def test_findings_from_no_rate_limit():
    probes = [{"probe": "rate_limit", "result": {
        "requests": 10, "statuses": [200], "median_seconds": 0.5,
        "max_seconds": 0.6, "throttled": False}}]
    findings = findings_from_probes(probes)
    assert any(f["level"] == "HIGH" and f["vector"] == "No rate limiting" for f in findings)


def test_findings_from_slowloris_patient():
    probes = [{"probe": "slowloris", "result": {
        "held_seconds": 40.0, "server_closed": False, "patient_to_deadline": True}}]
    findings = findings_from_probes(probes)
    assert any(f["level"] == "HIGH" and "Slowloris" in f["vector"] for f in findings)


def test_cli_help_and_subcommands():
    runner = CliRunner()
    assert runner.invoke(main, ["dos", "--help"]).exit_code == 0
    assert runner.invoke(main, ["dos", "assess", "--help"]).exit_code == 0
    assert runner.invoke(main, ["dos", "stress", "--help"]).exit_code == 0


def test_cli_assess_against_local(local_server, tmp_path):
    out = tmp_path / "dos.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "dos", "assess", local_server,
        "--probes", "http2,slowloris,rudy",
        "--slow-deadline", "3",
        "--json", str(out),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["target"] == local_server
    assert {p["probe"] for p in data["probes"]} == {"http2", "slowloris", "rudy"}


def test_cli_stress_requires_confirmation(local_server):
    runner = CliRunner()
    result = runner.invoke(main, [
        "dos", "stress", local_server, "--duration", "1", "--workers", "2",
    ], input="definitely-not-the-host\n")
    assert "Confirmation mismatch" in result.output or "Aborting" in result.output


def test_cli_stress_yes_runs(local_server):
    runner = CliRunner()
    result = runner.invoke(main, [
        "dos", "stress", local_server, "--yes",
        "--duration", "1.5", "--workers", "4", "--interval", "0.05",
    ])
    assert result.exit_code == 0, result.output
    assert "Done." in result.output
