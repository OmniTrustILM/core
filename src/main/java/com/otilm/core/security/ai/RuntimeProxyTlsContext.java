package com.otilm.core.security.ai;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import org.apache.tomcat.util.net.SSLContext;

final class RuntimeProxyTlsContext implements SSLContext {
    private final javax.net.ssl.SSLContext context;
    private final X509ExtendedKeyManager keys;

    RuntimeProxyTlsContext(X509ExtendedKeyManager keys, RuntimeProxyTrustManager trust)
            throws java.security.GeneralSecurityException {
        this.keys = keys;
        context = javax.net.ssl.SSLContext.getInstance("TLSv1.3", "SunJSSE");
        context.init(new KeyManager[]{keys}, new TrustManager[]{trust}, null);
        context.getServerSessionContext().setSessionCacheSize(1024);
        context.getServerSessionContext().setSessionTimeout(300);
    }

    @Override
    public void init(KeyManager[] suppliedKeys, TrustManager[] suppliedTrust, SecureRandom random)
            throws KeyManagementException {
        throw new KeyManagementException("Runtime TLS context is already initialized");
    }

    @Override
    public void destroy() {
        var sessions = context.getServerSessionContext();
        var identifiers = sessions.getIds();
        while (identifiers.hasMoreElements()) {
            var session = sessions.getSession(identifiers.nextElement());
            if (session != null) {
                session.invalidate();
            }
        }
    }

    @Override
    public SSLSessionContext getServerSessionContext() {
        return context.getServerSessionContext();
    }

    @Override
    public SSLEngine createSSLEngine() {
        return context.createSSLEngine();
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        return context.getServerSocketFactory();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        return context.getSupportedSSLParameters();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        var chain = keys.getCertificateChain(alias);
        return chain == null ? null : chain.clone();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
