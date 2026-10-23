#!/bin/bash
ADB="${ANDROID_SDK_ROOT:-$HOME/android-sdk}/platform-tools/platform-tools/adb"
FRIDA_VER=$(frida --version 2>/dev/null)
ARCH="${1:-x86_64}"

if [ -z "$FRIDA_VER" ]; then
  echo "[!] Frida not installed. Run: pip install frida-tools"
  exit 1
fi

echo "[*] Frida client version: $FRIDA_VER"
echo "[*] Target arch: $ARCH"

SERVER_FILE="/tmp/frida-server-${FRIDA_VER}-android-${ARCH}"

if [ ! -f "$SERVER_FILE" ]; then
  echo "[*] Downloading frida-server..."
  wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-${ARCH}.xz" \
    -O "${SERVER_FILE}.xz" && xz -d -f "${SERVER_FILE}.xz"
fi

echo "[*] Pushing to device..."
$ADB root && sleep 2
$ADB push "$SERVER_FILE" /data/local/tmp/frida-server
$ADB shell chmod 755 /data/local/tmp/frida-server

echo "[*] Starting frida-server..."
$ADB shell "pkill -f frida-server 2>/dev/null; /data/local/tmp/frida-server -D &"
sleep 2

echo "[*] Verifying..."
frida-ps -U 2>/dev/null | head -5
echo "[+] Frida server ready!"
