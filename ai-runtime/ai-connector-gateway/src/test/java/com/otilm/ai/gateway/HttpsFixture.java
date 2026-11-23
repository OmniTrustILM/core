package com.otilm.ai.gateway;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class HttpsFixture implements AutoCloseable {
    final AtomicInteger requests = new AtomicInteger();
    final AtomicReference<byte[]> received = new AtomicReference<>();
    final AtomicReference<String> authorization = new AtomicReference<>();
    final AtomicReference<String> path = new AtomicReference<>();
    final AtomicReference<String> contentType = new AtomicReference<>();
    final AtomicReference<String> acceptEncoding = new AtomicReference<>();
    final byte[] reply;
    final int status;
    String encoding;
    String redirect;
    boolean hostileChunked;
    boolean reset;
    final AtomicInteger chunksWritten = new AtomicInteger();
    final AtomicBoolean responseAborted = new AtomicBoolean();
    final CountDownLatch responseEnded = new CountDownLatch(1);
    private final HttpsServer server;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private final SSLContext clientTrust;
    final SSLContext serverTls;
    private final InetAddress address = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});

    HttpsFixture(int status, byte[] reply) throws Exception {
        this.status = status;
        this.reply = reply.clone();
        KeyPair caKeys = keys();
        var issuer = new X500Name("CN=F04 synthetic test CA");
        X509Certificate ca = certificate(issuer, issuer, caKeys, caKeys, true);
        KeyPair serverKeys = keys();
        X509Certificate leaf = certificate(issuer, new X500Name("CN=provider.invalid"), serverKeys, caKeys, false);
        var store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setKeyEntry("server", serverKeys.getPrivate(), new char[0], new X509Certificate[]{leaf, ca});
        var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(store, new char[0]);
        var tls = SSLContext.getInstance("TLS");
        tls.init(km.getKeyManagers(), null, new SecureRandom());
        serverTls = tls;
        var trusted = KeyStore.getInstance(KeyStore.getDefaultType());
        trusted.load(null, null);
        trusted.setCertificateEntry("test-ca", ca);
        var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(trusted);
        clientTrust = SSLContext.getInstance("TLS");
        clientTrust.init(null, tm.getTrustManagers(), new SecureRandom());
        server = HttpsServer.create(new InetSocketAddress(address, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.setExecutor(executor);
        server.createContext("/", exchange -> {
            try (exchange) {
                requests.incrementAndGet();
                path.set(exchange.getRequestURI().toString());
                received.set(exchange.getRequestBody().readNBytes(1048577));
                authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
                contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
                acceptEncoding.set(exchange.getRequestHeaders().getFirst("Accept-Encoding"));
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                if (status != 200) {
                    exchange.getResponseHeaders().set("Retry-After", "0");
                    exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer realm=synthetic");
                    exchange.getResponseHeaders().set("Proxy-Authenticate", "Basic realm=synthetic");
                }
                if (encoding != null) {
                    exchange.getResponseHeaders().set("Content-Encoding", encoding);
                }
                if (redirect != null) {
                    exchange.getResponseHeaders().set("Location", redirect);
                }
                if (hostileChunked) {
                    exchange.sendResponseHeaders(status, 0);
                    try {
                        byte[] chunk = new byte[65536];
                        for (int index = 0; index < 192; index++) {
                            exchange.getResponseBody().write(chunk);
                            exchange.getResponseBody().flush();
                            chunksWritten.incrementAndGet();
                        }
                    } catch (java.io.IOException closed) {
                        responseAborted.set(true);
                    } finally {
                        responseEnded.countDown();
                    }
                } else if (reset) {
                    exchange.close();
                } else if (status == 101) {
                    exchange.sendResponseHeaders(status, -1);
                } else {
                    exchange.sendResponseHeaders(status, this.reply.length);
                    exchange.getResponseBody().write(this.reply);
                }
            }
        });
        server.start();
    }

    PinnedEndpoint endpoint() {
        return endpoint("provider.invalid", clientTrust);
    }

    PinnedEndpoint endpoint(String host, SSLContext trust) {
        return new PinnedEndpoint(URI.create("https://" + host + ":" + server.getAddress().getPort()), List.of(address),
                trust);
    }

    private static KeyPair keys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(X500Name issuer, X500Name subject, KeyPair subjectKeys,
            KeyPair signingKeys, boolean ca) throws Exception {
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(128, new SecureRandom()),
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)), subject, subjectKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (!ca) {
            builder
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, "provider.invalid")));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signingKeys.getPrivate())));
    }

    @Override
    public void close() throws Exception {
        server.stop(0);
        executor.shutdownNow();
        if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
            throw new AssertionError("Owned fixture threads did not stop");
        }
    }
}
