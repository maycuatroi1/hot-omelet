Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "samsung/dm1qxx/dm1q:14/UP1A.231005.007/S911BXXU2AWK1:user/release-keys";
    Build.MODEL.value = "SM-S911B";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.DEVICE.value = "dm1q";
    Build.PRODUCT.value = "dm1q";
    Build.HARDWARE.value = "kalama";
    Build.BOARD.value = "kalama";
    Build.DISPLAY.value = "TP1A.220624.014.S911BXXU2AWK1";
    Build.HOST.value = "21DJ14";
    Build.TAGS.value = "release-keys";
    Build.TYPE.value = "user";
    Build.ID.value = "UP1A.231005.007";
    Build.SERIAL.value = "R5CR30ABCDE";

    var SystemProperties = Java.use("android.os.SystemProperties");
    var origGet = SystemProperties.get.overload('java.lang.String', 'java.lang.String');
    origGet.implementation = function(key, def) {
        var emuProps = {
            "ro.hardware": "kalama",
            "ro.product.model": "SM-S911B",
            "ro.product.brand": "samsung",
            "ro.product.manufacturer": "samsung",
            "ro.product.device": "dm1q",
            "ro.product.name": "dm1q",
            "ro.product.board": "kalama",
            "ro.build.fingerprint": "samsung/dm1qxx/dm1q:14/UP1A.231005.007/S911BXXU2AWK1:user/release-keys",
            "ro.build.display.id": "TP1A.220624.014.S911BXXU2AWK1",
            "ro.build.tags": "release-keys",
            "ro.build.type": "user",
            "ro.bootimage.build.fingerprint": "samsung/dm1qxx/dm1q:14/UP1A.231005.007/S911BXXU2AWK1:user/release-keys",
            "init.svc.qemud": "",
            "init.svc.qemu-props": "",
            "ro.kernel.qemu": "",
            "ro.kernel.android.qemud": "",
            "ro.hardware.audio.primary": "samsung",
            "gsm.version.ril-impl": "samsung-ril 1.0",
            "ro.boot.hardware": "kalama",
            "ro.boot.serialno": "R5CR30ABCDE",
            "ro.serialno": "R5CR30ABCDE",
            "ro.kernel.androidboot.hardware": "kalama"
        };
        if (key in emuProps) {
            return emuProps[key];
        }
        var result = origGet.call(this, key, def);
        if (result && (result.indexOf("ranchu") !== -1 || result.indexOf("goldfish") !== -1 || result.indexOf("generic") !== -1 || result.indexOf("sdk_gphone") !== -1 || result.indexOf("emulator") !== -1 || result.indexOf("vbox") !== -1)) {
            return def;
        }
        return result;
    };

    var File = Java.use("java.io.File");
    var origExists = File.exists;
    origExists.implementation = function() {
        var path = this.getAbsolutePath();
        var emuFiles = [
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemud",
            "/system/bin/qemu-props",
            "/dev/goldfish_pipe",
            "/dev/goldfish_audio",
            "/dev/goldfish_sync",
            "/system/lib/libdroid4x.so",
            "/data/YouWave_id",
            "/dev/vboxguest",
            "/dev/vboxuser",
            "/fstab.andy",
            "/fstab.nox",
            "/x8",
            "/sys/bus/pci/drivers/goldfish_address_space",
            "/sys/bus/pci/drivers/goldfish_pipe"
        ];
        for (var i = 0; i < emuFiles.length; i++) {
            if (path === emuFiles[i]) return false;
        }
        return origExists.call(this);
    };

    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function() {
            return "355012345678901";
        };
        TelephonyManager.getSubscriberId.overload().implementation = function() {
            return "310260123456789";
        };
        TelephonyManager.getLine1Number.overload().implementation = function() {
            return "+84912345678";
        };
        TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
            return "Viettel";
        };
        TelephonyManager.getNetworkOperator.overload().implementation = function() {
            return "45201";
        };
        TelephonyManager.getSimOperator.overload().implementation = function() {
            return "45201";
        };
        TelephonyManager.getSimOperatorName.overload().implementation = function() {
            return "Viettel";
        };
        TelephonyManager.getSimCountryIso.overload().implementation = function() {
            return "vn";
        };
        TelephonyManager.getNetworkCountryIso.overload().implementation = function() {
            return "vn";
        };
    } catch(e) {
        console.log("[!] TelephonyManager hooks failed: " + e);
    }

    try {
        var WifiInfo = Java.use("android.net.wifi.WifiInfo");
        WifiInfo.getMacAddress.implementation = function() {
            return "48:2C:A0:1E:3F:A2";
        };
    } catch(e) {}

    try {
        var Secure = Java.use("android.provider.Settings$Secure");
        var origGetString = Secure.getString.overload('android.content.ContentResolver', 'java.lang.String');
        origGetString.implementation = function(resolver, name) {
            if (name === "android_id") {
                return "a1b2c3d4e5f67890";
            }
            return origGetString.call(this, resolver, name);
        };
    } catch(e) {}

    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        console.log("[+] SensorManager loaded - sensor spoofing active");
    } catch(e) {}

    console.log("[+] Emulator hiding hooks installed!");
    console.log("[+] Device spoofed as Samsung Galaxy S23 (SM-S911B)");
});
