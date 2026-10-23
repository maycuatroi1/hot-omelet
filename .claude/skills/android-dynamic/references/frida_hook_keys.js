Java.perform(function() {
    var Utils = Java.use("com.zing.zalo.utils.cryptology.Utils");

    Utils.getStaticValue.overload('android.content.Context', 'int', '[B').implementation = function(ctx, type, data) {
        var result = this.getStaticValue(ctx, type, data);
        var hexResult = Array.prototype.map.call(Java.array('byte', result), function(b) {
            return ('0' + ((b & 0xff).toString(16))).slice(-2);
        }).join('');
        console.log("[*] getStaticValue(type=" + type + ", data=" + data + ")");
        console.log("[*] Result (hex): " + hexResult);
        console.log("[*] Result (len): " + result.length);
        return result;
    };

    var C10179g = Java.use("com.zing.zalo.p079db.C10179g");
    console.log("[*] Server enum values:");
    var values = C10179g.values();
    for (var i = 0; i < values.length; i++) {
        var v = values[i];
        console.log("[*]   " + v.name() + " = " + v.f77041d + ":" + v.f77042e);
    }

    var AbstractC38439x0 = Java.use("st.AbstractC38439x0");
    var methods = AbstractC38439x0.class.getDeclaredMethods();
    console.log("[*] API builder methods: " + methods.length);

    try {
        var HandlerC22199b = Java.use("ee0.HandlerC22199b");
        console.log("[*] PlatformService handler loaded");
    } catch(e) {
        console.log("[!] Could not hook PlatformService handler: " + e);
    }

    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        if (key.toLowerCase().indexOf("token") !== -1 ||
            key.toLowerCase().indexOf("key") !== -1 ||
            key.toLowerCase().indexOf("secret") !== -1 ||
            key.toLowerCase().indexOf("session") !== -1 ||
            key.toLowerCase().indexOf("auth") !== -1 ||
            key.toLowerCase().indexOf("cookie") !== -1 ||
            key.toLowerCase().indexOf("password") !== -1) {
            console.log("[*] SharedPrefs.getString('" + key + "') = " + result);
        }
        return result;
    };

    var URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(url) {
        if (url && url.indexOf("zalo") !== -1) {
            console.log("[*] URL: " + url);
        }
        return this.$init(url);
    };

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");
        console.log("[*] OkHttp interceptor ready");
    } catch(e) {}

    console.log("[+] All hooks installed successfully!");
    console.log("[+] Login vào Zalo để capture API keys...");
});
