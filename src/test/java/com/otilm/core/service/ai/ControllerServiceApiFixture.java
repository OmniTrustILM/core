package com.otilm.core.service.ai;

import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.proxy.CoreEndpoint;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Authenticated local API wire only; no native deployment or business authority. */
final class ControllerServiceApiFixture implements AutoCloseable {
    record Reply(int status, byte[] body) {
    }

    private record Identity(KeyPair keys, X509Certificate certificate) {
    }

    final AtomicInteger requests = new AtomicInteger();
    final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final HttpsServer server;
    private final java.util.concurrent.ExecutorService executor = Executors.newFixedThreadPool(2);
    private final KubernetesConfiguration configuration;
    volatile Function<String, Reply> responder;

    ControllerServiceApiFixture(Path directory) throws Exception {
        var ca = identity(null, true);
        var leaf = identity(ca, false);
        var store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store
                .setKeyEntry("server", leaf.keys().getPrivate(), new char[0],
                        new X509Certificate[]{leaf.certificate(), ca.certificate()});
        var managers = KeyManagerFactory.getInstance("SunX509");
        managers.init(store, new char[0]);
        var tls = SSLContext.getInstance("TLS");
        tls.init(managers.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.setExecutor(executor);
        var roots = Files.createTempFile(directory, "controller-service-ca-", ".der");
        Files.write(roots, ca.certificate().getEncoded());
        var token = Files.createTempFile(directory, "controller-service-token-", ".txt");
        Files.writeString(token, "synthetic.controller.token");
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        configuration = new KubernetesConfiguration(
                new CoreEndpoint(URI.create("https://kube.invalid:" + server.getAddress().getPort()),
                        InetAddress.getLoopbackAddress()),
                roots, token);
        server.createContext("/", exchange -> {
            try (exchange) {
                requests.incrementAndGet();
                if (!"GET".equals(exchange.getRequestMethod()) || !"Bearer synthetic.controller.token"
                        .equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                    throw new AssertionError("Unexpected synthetic API request");
                }
                Reply reply = responder.apply(exchange.getRequestURI().toString());
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(reply.status(), reply.body().length);
                exchange.getResponseBody().write(reply.body());
            } catch (Throwable invalid) {
                failure.compareAndSet(null, invalid);
            }
        });
        server.start();
    }

    KubernetesConfiguration configuration() {
        return configuration;
    }

    private static Identity identity(Identity ca, boolean authority) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var keys = generator.generateKeyPair();
        var subject = new X500Name(authority ? "CN=synthetic controller service CA" : "CN=kube.invalid");
        var issuer = ca == null ? subject : new X500Name(ca.certificate().getSubjectX500Principal().getName());
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(issuer, java.math.BigInteger.valueOf(Math.abs(System.nanoTime())),
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(600)), subject, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(authority));
        builder
                .addExtension(Extension.keyUsage, true,
                        new KeyUsage(authority ? KeyUsage.keyCertSign : KeyUsage.digitalSignature));
        if (!authority) {
            builder
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, "kube.invalid")));
        }
        return new Identity(keys,
                new JcaX509CertificateConverter()
                        .getCertificate(builder
                                .build(new JcaContentSignerBuilder("SHA256withECDSA")
                                        .build(ca == null ? keys.getPrivate() : ca.keys().getPrivate()))));
    }

    @Override
    public void close() throws Exception {
        server.stop(0);
        executor.shutdownNow();
        if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
            throw new AssertionError("Synthetic controller API executor remained alive");
        }
    }
}
