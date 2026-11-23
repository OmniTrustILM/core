package com.otilm.ai.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic wire fixture: reads actual TLS/HTTP requests, never a client mock. */
final class LocalTlsFixture implements AutoCloseable {
    record Material(KeyPair keys, X509Certificate certificate) {
    }

    final Path directory;
    final Material ca;
    final Material client;
    final SSLServerSocket listener;
    final AtomicInteger requests = new AtomicInteger();
    final AtomicInteger connections = new AtomicInteger();
    final List<SSLSocket> peers = new CopyOnWriteArrayList<>();
    volatile String requestHeaders = "";
    volatile String requiredPath;
    volatile byte[] requestBody = new byte[0];
    volatile BigInteger peerSerial;
    volatile byte[] response;
    volatile boolean reset;
    volatile boolean stall;
    volatile boolean drip;
    volatile boolean stallAfterResponse;
    final java.util.concurrent.CompletableFuture<Void> requestArrived = new java.util.concurrent.CompletableFuture<>();
    final java.util.concurrent.CompletableFuture<Void> peerFinished = new java.util.concurrent.CompletableFuture<>();
    volatile boolean closed;
    final Thread acceptor;

    LocalTlsFixture(Path directory) throws Exception {
        this(directory, "core.test", false);
    }

    LocalTlsFixture(Path directory, String hostname, boolean expiredServer) throws Exception {
        this.directory = Files.createDirectories(directory);
        ca = material("fixture-ca", null, true, null, false, "secp256r1");
        client = material("fixture-client", ca, false, null, false, "secp256r1");
        Material server = material(hostname, ca, false, hostname, expiredServer, "secp256r1");
        writeClient(directory, client);
        writePem(directory.resolve("ca.pem"), "CERTIFICATE", ca.certificate().getEncoded());
        listener = (SSLServerSocket) context(server, ca)
                .getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        listener.setNeedClientAuth(true);
        listener.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        respond(200, "", ProxyWireFixtures.PENDING);
        acceptor = Thread.ofPlatform().daemon().name("synthetic-core-accept").start(this::accept);
    }

    ProxyConfiguration configuration() {
        return new ProxyConfiguration(URI.create("https://core.test:" + listener.getLocalPort()),
                InetAddress.getLoopbackAddress(), directory.resolve("tls.crt"), directory.resolve("tls.key"),
                directory.resolve("ca.pem"));
    }

    void respond(int status, String headers, byte[] body) {
        byte[] prefix = ("HTTP/1.1 " + status + " Fixture\r\nContent-Type: application/json\r\nContent-Length: "
                + body.length + "\r\nConnection: close\r\n" + headers + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        response = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, response, 0, prefix.length);
        System.arraycopy(body, 0, response, prefix.length, body.length);
    }

    private void accept() {
        while (!closed) {
            try {
                SSLSocket peer = (SSLSocket) listener.accept();
                peers.add(peer);
                connections.incrementAndGet();
                Thread.ofPlatform().daemon().name("synthetic-core-peer").start(() -> serve(peer));
            } catch (IOException failure) {
                if (!closed) {
                    throw new AssertionError(failure);
                }
            }
        }
    }

    private void serve(SSLSocket peer) {
        try (peer) {
            peer.setSoTimeout(7000);
            peer.startHandshake();
            peerSerial = ((X509Certificate) peer.getSession().getPeerCertificates()[0]).getSerialNumber();
            var input = peer.getInputStream();
            var header = new ByteArrayOutputStream();
            int match = 0;
            while (match < 4) {
                int b = input.read();
                if (b < 0 || header.size() > 16384) {
                    return;
                }
                header.write(b);
                match = b == "\r\n\r\n".charAt(match) ? match + 1 : (b == '\r' ? 1 : 0);
            }
            requestHeaders = header.toString(StandardCharsets.ISO_8859_1);
            int length = 0;
            for (String line : requestHeaders.split("\r\n")) {
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                    length = Integer.parseInt(line.substring(15).trim());
                }
            }
            if (length < 0 || length > 4096) {
                throw new AssertionError("unexpected request length");
            }
            requestBody = input.readNBytes(length);
            if (requestBody.length != length) {
                return;
            }
            requests.incrementAndGet();
            requestArrived.complete(null);
            if (reset) {
                peer.setSoLinger(true, 0);
                return;
            }
            if (stall) {
                while (input.read() != -1) {
                }
                return;
            }
            if (drip) {
                for (byte value : response) {
                    peer.getOutputStream().write(value);
                    peer.getOutputStream().flush();
                    Thread.sleep(100);
                }
                return;
            }
            byte[] reply = requiredPath != null && !requestHeaders.startsWith("POST " + requiredPath + " HTTP/1.1\r\n")
                    ? "HTTP/1.1 404 Missing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .getBytes(StandardCharsets.ISO_8859_1)
                    : response;
            peer.getOutputStream().write(reply);
            peer.getOutputStream().flush();
            if (stallAfterResponse) {
                while (input.read() != -1) {
                }
            }
        } catch (Exception expectedHandshakeOrAbort) {
            // Negative TLS tests and client deadlines deliberately abort this side.
        } finally {
            peers.remove(peer);
            peerFinished.complete(null);
        }
    }

    static Material material(String name, Material issuer, boolean ca, String hostname, boolean expired, String curve)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=" + name);
        X500Name issuerName = issuer == null
                ? subject
                : new X500Name(issuer.certificate().getSubjectX500Principal().getName());
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(issuerName, new BigInteger(120, new SecureRandom()),
                Date.from(now.minusSeconds(expired ? 7200 : 60)), Date.from(now.plusSeconds(expired ? -3600 : 86400)),
                subject, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder
                .addExtension(Extension.keyUsage, true,
                        new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (!ca) {
            builder
                    .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                            hostname == null ? KeyPurposeId.id_kp_clientAuth : KeyPurposeId.id_kp_serverAuth));
        }
        if (hostname != null) {
            builder
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
        }
        var signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(issuer == null ? pair.getPrivate() : issuer.keys().getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return new Material(pair, certificate);
    }

    static void writeClient(Path directory, Material material) throws Exception {
        Files.createDirectories(directory);
        writePem(directory.resolve("tls.crt"), "CERTIFICATE", material.certificate().getEncoded());
        writePem(directory.resolve("tls.key"), "PRIVATE KEY", material.keys().getPrivate().getEncoded());
    }

    static void writePem(Path path, String label, byte[] der) throws IOException {
        Files
                .writeString(path,
                        "-----BEGIN " + label + "-----\n"
                                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der) + "\n-----END "
                                + label + "-----\n",
                        StandardCharsets.US_ASCII);
    }

    private static SSLContext context(Material own, Material trusted) throws Exception {
        char[] password = new char[0];
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys
                .setKeyEntry("own", own.keys().getPrivate(), password,
                        new java.security.cert.Certificate[]{own.certificate(), trusted.certificate()});
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, password);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("fixture", trusted.certificate());
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        return context;
    }

    @Override
    public void close() throws Exception {
        closed = true;
        listener.close();
        for (SSLSocket peer : peers) {
            peer.close();
        }
        acceptor.join(1000);
    }
}
