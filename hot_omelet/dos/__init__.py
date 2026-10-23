"""
DoS exposure assessment package (authorized targets only).

`assess` measures a web server's exposure to denial-of-service vectors with
polite, low-volume probes (single connections, a handful of requests) and
reports findings. `stress` runs an explicit, confirmation-gated load test
against infrastructure you own.

Vectors covered (validated against real Moodle/Apache deployments):
- HTTP/2 ALPN exposure (CONTINUATION flood / Rapid Reset class)
- Slow-header tolerance (Slowloris) and slow-body tolerance (RUDY)
- Auth-endpoint CPU cost asymmetry (bcrypt verify per failed login)
- Rate limiting / lockout presence on auth endpoints
- Worker-pool saturation estimate under a small parallel burst
- Password-reset email amplification
"""

from hot_omelet.dos.engine import dos_assess_command
from hot_omelet.dos.stress import dos_stress_command

__all__ = ["dos_assess_command", "dos_stress_command"]
