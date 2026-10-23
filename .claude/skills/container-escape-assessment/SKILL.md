---
name: container-escape-assessment
description: Systematic benign enumeration of container escape vectors - capabilities, namespaces, cgroups, seccomp, kernel isolation. Use when you have code execution inside a Docker/containerd/Kubernetes container and want to assess whether you can break out to the host - check for privileged mode, dangerous capabilities (CAP_SYS_ADMIN), mounted docker.sock, host namespace sharing, and writable cgroup release_agent, before attempting any escape.
---

## When to use

After achieving RCE inside a containerized target (Docker, Kubernetes) and needing to assess container escape feasibility. Run benign, read-only checks only — no privilege escalation attempts or kernel exploits.

## How it works

The methodology systematically probes each container isolation primitive without triggering exploits:

1. **Capabilities**: Check `CapEff` (must be 0 for hardened), `CapBnd` (boundary mask), `CapPrm` (permitted), `CapAmb` (ambient). Effective = 0 blocks SYS_ADMIN, NET_ADMIN, SYS_PTRACE.
2. **Unprivileged namespace**: Test `unshare -Ur id` — benign check if `unprivileged_userns_clone=1` is exposed. EPERM = seccomp blocks `clone(CLONE_NEWUSER)` (blocks CVE-2024-1086 class kernel LPE).
3. **Docker/K8s sockets**: Enumerate `/var/run/` for `docker.sock`, Kubernetes serviceaccount tokens, CRI sockets.
4. **Privileged mounts**: Look for host block devices (`/dev/sda*`), host fs bind mounts (not just `resolv.conf`).
5. **cgroup v1 release_agent** (kernel LPE): Only relevant if cgroup v1; v2 is immune. Check ownership/permissions.
6. **/proc knobs** (core_pattern, sysrq, modprobe): Root-owned or read-only = safe.
7. **SUID binaries**: Count binaries with setuid bit inside container. Zero = container root unreachable from uid≠0.
8. **Namespace isolation**: Check if PID/net/user namespaces are separate from host (init userns = host, unshare output = isolated).
9. **Seccomp**: Detect seccomp filter presence via strace/perf or benign syscall tests.

Document each vector as **✅ blocked** (result), **❌ not applicable**, or **⚠️ exploitable** with root cause.

## Example

```bash
# 1. Extract/create probe script for target
cat > /tmp/escape_probe.sh <<'PROBE'
echo "=== capabilities ==="
grep -E 'Cap(Eff|Bnd|Prm|Amb)' /proc/self/status
echo "=== userns (benign) ==="
unshare -Ur id || echo "blocked (seccomp/policy)"
echo "=== docker socket ==="
ls -la /var/run/docker.sock 2>&1 || echo "not found"
echo "=== suid binaries ==="
find / -perm -4000 2>/dev/null | wc -l
PROBE

# 2. Execute through live RCE vector (e.g. PostgreSQL)
B=$(base64 < /tmp/escape_probe.sh | tr -d '\n')
python3 workers/TARGET/connect.py exec "echo $B | base64 -d | /bin/sh"

# 3. Save output with timestamp
OUT=workers/TARGET/evidence/container_escape_assessment_$(date +%Y%m%d).txt
# ... capture and store ...

# 4. Create matrix in README: Vector | Result | Root cause | Exploitable?
```

## Why it matters

Containers often *look* breached (uid 0 = root, lots of capabilities) but are actually hardened (seccomp, CapEff=0, cgroup v2). Systematic enumeration distinguishes between:
- **Hardened** (all vectors blocked, blast radius = container only)
- **Weakly isolated** (namespace misconfig, cgroup v1, SUID binary, userns enabled)
- **Privileged** (host FS mounts, device pass-through, no seccomp)

Result informs lateral movement strategy: pivot to other services, exfiltrate creds, or escalate to host depends entirely on container hardening.

## Related

Use `/red-team-post-exploit` or `/validate` to confirm escape feasibility if a vector is flagged as exploitable.
