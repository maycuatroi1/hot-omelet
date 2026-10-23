Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
        console.log('[*] SSLContext.init intercepted - bypassing SSL pinning');
        this.init(km, [TrustManager.$new()], sr);
    };

    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[*] OkHttp CertificatePinner bypass for: ' + hostname);
        };
    } catch(e) {}

    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function() {
            console.log('[*] Conscrypt TrustManagerImpl bypass');
            return arguments[0];
        };
    } catch(e) {}

    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityConfig.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, authType) {
            console.log('[*] NetworkSecurityConfig bypass');
        };
    } catch(e) {}

    console.log('[+] SSL Pinning bypass installed!');
});
