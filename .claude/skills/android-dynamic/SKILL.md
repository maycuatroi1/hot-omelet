---
name: android-dynamic
description: Android dynamic analysis with emulator and Frida. Use when asked to "run android app", "frida hook", "start emulator", "dynamic analysis apk", "intercept traffic", "bypass ssl pinning", "hide emulator", "extract api keys", "hook native function", "android pentest", or any Android dynamic instrumentation task.
---

# Android Dynamic Analysis

Dynamic analysis toolkit for Android APK security testing using emulator + Frida.

## Environment Setup

### Emulator Management (via Makefile)

```bash
make emu-start          # Start emulator (foreground)
make emu-start-bg       # Start emulator (background)
make emu-stop           # Kill emulator
make emu-root           # Root + remount system
make emu-reboot         # Reboot emulator
make emu-shell          # ADB shell
make emu-status         # Check emulator status
```

### Emulator Config

- **AVD**: `pentest` at `~/.android/avd/pentest.avd/`
- **Image**: Android 14 (API 34), Google APIs x86_64 with ARM translation
- **Root**: Yes (Google APIs image allows `adb root`)
- **System**: Writable (`-writable-system` flag)
- **KVM**: Required (`sg kvm -c` wrapper for permissions)
- **Display**: WSLg via `DISPLAY=:0`

### Key Paths

```
~/android-sdk/                              # SDK root
~/android-sdk/platform-tools/platform-tools/adb   # ADB binary
~/android-sdk/emulator/emulator             # Emulator binary
~/.android/avd/pentest.avd/config.ini       # AVD config
```

## Frida Operations

### Server Management

```bash
make frida-server-push   # Push frida-server to device
make frida-server-start  # Root + start frida-server
make frida-ps            # List running processes
```

### Attaching to Apps

```bash
# Generic attach (works for any app)
make frida-attach APP="com.example.app" SCRIPT=path/to/script.js

# Or attach directly with the frida CLI
frida -U -f com.example.app -l scripts/frida_hook_keys.js --no-pause
frida -U -n "AppName" -l scripts/frida_ssl_bypass.js
```

### Frida Server Setup on Device

```bash
ADB=~/android-sdk/platform-tools/platform-tools/adb
$ADB root
$ADB push /tmp/frida-server /data/local/tmp/frida-server
$ADB shell chmod 755 /data/local/tmp/frida-server
$ADB shell "/data/local/tmp/frida-server -D &"
```

Frida-server version must match client: `frida --version`
Download from: `https://github.com/frida/frida/releases/download/<VER>/frida-server-<VER>-android-x86_64.xz`

## Device Spoofing

### Build.prop Spoofing (persist across reboots)

After `adb root && adb remount`, append to `/system/build.prop`, `/vendor/build.prop`, `/product/build.prop`:

```properties
ro.product.manufacturer=samsung
ro.product.brand=samsung
ro.product.model=SM-S911B
ro.product.device=dm1q
ro.build.fingerprint=samsung/dm1qxx/dm1q:14/UP1A.231005.007/S911BXXU2AWK1:user/release-keys
ro.build.tags=release-keys
ro.build.type=user
```

### Frida Runtime Spoofing

The `frida_hide_emu.js` script hooks:
- `android.os.Build` fields (MODEL, MANUFACTURER, FINGERPRINT, etc.)
- `android.os.SystemProperties.get()` - filters emulator props (ranchu, goldfish, generic)
- `java.io.File.exists()` - hides emulator files (/dev/qemu_pipe, /dev/goldfish_pipe, etc.)
- `TelephonyManager` - returns fake IMEI, carrier, SIM info
- `WifiInfo.getMacAddress()` - returns fake MAC
- `Settings.Secure.getString()` - returns fake android_id

## Frida Script Templates

### Hook Java Method

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.ClassName");
    TargetClass.methodName.overload('java.lang.String').implementation = function(arg) {
        console.log("[*] methodName called: " + arg);
        var result = this.methodName(arg);
        console.log("[*] result: " + result);
        return result;
    };
});
```

### Hook Native Function

```javascript
var nativeFunc = Module.findExportByName("libnative.so", "functionName");
Interceptor.attach(nativeFunc, {
    onEnter: function(args) {
        console.log("[*] arg0: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[*] retval: " + retval);
    }
});
```

### Enumerate Loaded Classes

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("target") !== -1) {
                console.log("[*] " + className);
            }
        },
        onComplete: function() {}
    });
});
```

### Dump SharedPreferences

```javascript
Java.perform(function() {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        if (result !== null && result.length > 0) {
            console.log("[*] SharedPrefs: " + key + " = " + result);
        }
        return result;
    };
});
```

### Intercept HTTP/URL Requests

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log("[*] URL: " + url);
        return this.$init(url);
    };
});
```

## App-Specific Analysis

### Available Scripts

| Script | Purpose |
|--------|---------|
| `frida_hide_emu.js` | Emulator detection bypass + device spoof |
| `frida_hook_keys.js` | Extract API encryption keys from native code |
| `frida_ssl_bypass.js` | SSL pinning bypass for traffic interception |

### Quick Start

```bash
make emu-start-bg        # Start emulator
# Wait for boot...
adb install target.apk   # Install the app under test
make frida-server-start  # Root + start frida-server
frida -U -f com.example.app -l scripts/frida_hide_emu.js --no-pause
```

### Finding Hook Targets

Start from what you know about the app, then refine:

| Starting point | How to explore |
|----------------|----------------|
| Native crypto (`lib*.so`) | `frida_hook_keys.js` hooks `Module.findExportByName` targets |
| Obfuscated handlers (`a1.HandlerX`, `st.AbstractCX`) | Hook `handleMessage` and trace message flow |
| API endpoint builders | Hook `java.net.URL` / OkHttp `Interceptor` chain |
| Server infrastructure maps | Dump enum values and static config classes |

Use `Java.enumerateLoadedClasses` (template above) filtered on app keywords
to discover the real class names behind obfuscation.

### Traffic Interception Setup

1. Start mitmproxy: `mitmproxy --listen-port 8080`
2. Set proxy on emulator: `adb shell settings put global http_proxy 10.0.2.2:8080`
3. Install mitmproxy CA: `adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/`
4. Attach SSL bypass: `frida -U -n "AppName" -l scripts/frida_ssl_bypass.js`
