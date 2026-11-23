package com.otilm.ai.gateway;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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

/** Synthetic Core-shaped mTLS and independent provider wire oracle; no business authorization. */
final class GatewayRunFixture implements AutoCloseable {
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();
    private static final com.otilm.ai.runtime.protocol.ProtocolCodec PROTOCOL = new com.otilm.ai.runtime.protocol.ProtocolCodec();
    static final String TOKEN = "SYNTHETIC_TRANSPORT_CANARY";
    final Path directory, config, envelope, secret;
    final HttpsServer core, provider;
    final SSLContext coreServerTls;
    final java.util.concurrent.ExecutorService threads = Executors.newFixedThreadPool(4);
    final AtomicInteger consumes = new AtomicInteger(), outcomes = new AtomicInteger(), sends = new AtomicInteger();
    final AtomicInteger coreRequests = new AtomicInteger();
    final AtomicInteger registrations = new AtomicInteger();
    volatile int pendingRegistrationReplies;
    volatile long registrationDelayMillis;
    private volatile boolean closing;
    final AtomicInteger registrationDelaysStoppedByOwner = new AtomicInteger();
    volatile String registrationMode = "ready";
    final java.util.List<String> coreTrace = new java.util.concurrent.CopyOnWriteArrayList<>();
    final java.util.concurrent.atomic.AtomicBoolean coreSawAuthorization = new java.util.concurrent.atomic.AtomicBoolean(),
            coreSawCookie = new java.util.concurrent.atomic.AtomicBoolean();
    final java.util.concurrent.atomic.AtomicReference<Throwable> fixtureFailure = new java.util.concurrent.atomic.AtomicReference<>();
    volatile byte[] providerRequest, outcomeRequest;
    volatile byte[] consumeRequest;
    volatile String providerAuthorization, providerCookie, coreAuthorization;
    volatile boolean providerReceivedClientIdentity;
    volatile String mode = "success";
    volatile int providerStatus = 200;
    volatile long consumeDelayMillis;
    volatile byte[] providerReply = "{\"model\":\"lab\",\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"public reply\"}}]}"
            .getBytes(StandardCharsets.UTF_8);

    GatewayRunFixture(Path directory) throws Exception {
        this(directory, "");
    }

    GatewayRunFixture(Path directory, String context) throws Exception {
        this(directory, context, null);
    }

    GatewayRunFixture(Path directory, String context, com.otilm.ai.runtime.protocol.ManagementAction managementAction)
            throws Exception {
        boolean management = managementAction != null;
        var dispatch = management ? GatewayManagementWireTest.envelope(managementAction) : GatewayRunWireTest.ENVELOPE;
        String kind = management ? "management" : "run";
        String route = context
                + (management ? "/internal/ai-management/v1/gateway/" : "/internal/ai-runtime/v1/gateway/run/");
        this.directory = Files.createDirectories(directory);
        config = directory.resolve("config.json");
        envelope = directory.resolve("envelope.json");
        secret = directory.resolve("private.json");
        Material coreCa = material("core-ca", null, true, null),
                client = material("gateway-" + kind, coreCa, false, null),
                coreLeaf = material("core.test", coreCa, false, "core.test");
        Material providerCa = material("provider-ca", null, true, null),
                providerLeaf = material("provider.test", providerCa, false, "provider.test");
        pem(directory.resolve("tls.crt"), "CERTIFICATE", client.certificate.getEncoded());
        pem(directory.resolve("tls.key"), "PRIVATE KEY", client.keys.getPrivate().getEncoded());
        pem(directory.resolve("ca.pem"), "CERTIFICATE", coreCa.certificate.getEncoded());
        pem(directory.resolve("provider-ca.pem"), "CERTIFICATE", providerCa.certificate.getEncoded());
        coreServerTls = tls(coreLeaf, coreCa);
        core = server(coreServerTls, true);
        // Adversarial oracle: offer Core's issuer too, so copied Core key managers cannot hide behind issuer filtering.
        provider = server(tls(providerLeaf, providerCa, coreCa), false);
        core.createContext(context + "/internal/", exchange -> {
            try (exchange) {
                coreRequests.incrementAndGet();
                if ("GET".equals(exchange.getRequestMethod())
                        && exchange.getRequestURI().getRawPath().equals(route + "registration")) {
                    int count = registrations.incrementAndGet();
                    coreTrace.add("registration");
                    if (exchange.getRequestURI().getRawQuery() != null || exchange.getRequestBody().read() != -1
                            || exchange.getRequestHeaders().getFirst("Content-Type") != null
                            || exchange.getRequestHeaders().getFirst("Authorization") != null
                            || exchange.getRequestHeaders().getFirst("Cookie") != null) {
                        throw new AssertionError("Registration accepted a synthetic selector or body");
                    }
                    if (registrationDelayMillis > 0) {
                        try {
                            Thread.sleep(registrationDelayMillis);
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            if (!closing) {
                                throw interrupted;
                            }
                            registrationDelaysStoppedByOwner.incrementAndGet();
                            return;
                        }
                    }
                    if (registrationMode.equals("reset")) {
                        return;
                    }
                    String state = registrationMode.equals("pending") || count <= pendingRegistrationReplies
                            ? "pending"
                            : "ready";
                    String selected = registrationMode.equals("opposite-kind")
                            ? (management ? "run" : "management")
                            : kind;
                    String document = "{\"version\":1,\"kind\":\"" + selected + "-gateway-registration-" + state
                            + "\"}";
                    if (registrationMode.equals("extra")) {
                        document = document.substring(0, document.length() - 1) + ",\"runId\":\"synthetic-selector\"}";
                    } else if (registrationMode.equals("duplicate")) {
                        document = document.replace("\"version\":1", "\"version\":1,\"version\":1");
                    } else if (registrationMode.equals("trailing")) {
                        document += " {}";
                    }
                    byte[] response = document
                            .getBytes(registrationMode.equals("utf16")
                                    ? StandardCharsets.UTF_16
                                    : StandardCharsets.UTF_8);
                    String media = registrationMode.equals("comma-type")
                            ? "application/json, text/plain"
                            : "application/json";
                    exchange.getResponseHeaders().set("Content-Type", media);
                    if (registrationMode.equals("duplicate-type")) {
                        exchange.getResponseHeaders().add("Content-Type", "application/json");
                    }
                    if (registrationMode.equals("cookie")) {
                        exchange.getResponseHeaders().set("Set-Cookie", "SYNTHETIC_SESSION_CANARY");
                    }
                    if (registrationMode.equals("encoding")) {
                        exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                    }
                    int code = switch (registrationMode) {
                        case "redirect" -> 302;
                        case "401" -> 401;
                        case "407" -> 407;
                        case "503" -> 503;
                        default -> 200;
                    };
                    if (code == 302) {
                        exchange.getResponseHeaders().set("Location", "https://unaccepted.invalid/");
                    }
                    exchange.sendResponseHeaders(code, response.length);
                    exchange.getResponseBody().write(response);
                    return;
                }
                if (!"POST".equals(exchange.getRequestMethod()) || exchange.getRequestURI().getRawQuery() != null
                        || (!exchange.getRequestURI().getRawPath().equals(route + "redeem")
                                && !exchange.getRequestURI().getRawPath().equals(route + "outcomes"))) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                byte[] input = exchange.getRequestBody().readNBytes(1_500_001);
                coreAuthorization = exchange.getRequestHeaders().getFirst("Authorization");
                if (coreAuthorization != null) {
                    coreSawAuthorization.set(true);
                }
                if (exchange.getRequestHeaders().getFirst("Cookie") != null) {
                    coreSawCookie.set(true);
                }
                byte[] output;
                int status = 200;
                if (exchange.getRequestURI().getPath().endsWith("/redeem")) {
                    consumes.incrementAndGet();
                    coreTrace.add("consume");
                    consumeRequest = input;
                    if (consumeDelayMillis > 0) {
                        try {
                            Thread.sleep(consumeDelayMillis);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    var request = JSON.readTree(input);
                    var root = management
                            ? GatewayManagementWireTest.consumed(managementAction)
                            : GatewayRunWireTest.consumed();
                    root.put("gatewayCorrelation", request.get("gatewayCorrelation").textValue());
                    root.put("origin", "https://provider.test:" + provider.getAddress().getPort());
                    if (mode.equals("wrong-binding")) {
                        ((com.fasterxml.jackson.databind.node.ObjectNode) root.get("binding"))
                                .put(management ? "configurationRevision" : "fence", 99);
                    }
                    if (mode.equals("wrong-kind")) {
                        root.put("kind", management ? "run-consumed" : "management-consumed");
                    }
                    if (mode.equals("deny")) {
                        status = 403;
                        output = "{}".getBytes(StandardCharsets.UTF_8);
                    } else {
                        output = JSON.writeValueAsBytes(root);
                    }
                    if (mode.equals("cookie")) {
                        exchange.getResponseHeaders().add("Set-Cookie", "PRIVATE_CORE_SESSION_CANARY");
                    }
                } else {
                    outcomes.incrementAndGet();
                    coreTrace.add("outcome");
                    outcomeRequest = input;
                    var request = JSON.readTree(input);
                    var ack = JSON
                            .createObjectNode()
                            .put("protocolVersion", 1)
                            .put("kind", kind + "-outcome-recorded")
                            .put("intentId", request.get("intentId").textValue())
                            .put("gatewayCorrelation", request.get("gatewayCorrelation").textValue())
                            .put("outcomeSha256", mode.equals("bad-ack")
                                    ? "a".repeat(64)
                                    : java.util.HexFormat
                                            .of()
                                            .formatHex(
                                                    java.security.MessageDigest.getInstance("SHA-256").digest(input)))
                            .put("resultVersion", 9);
                    output = JSON.writeValueAsBytes(ack);
                }
                if (!mode.equals("no-mime")) {
                    exchange
                            .getResponseHeaders()
                            .set("Content-Type",
                                    mode.equals("mime")
                                            ? "text/plain"
                                            : mode.equals("charset")
                                                    ? "application/json;charset=ISO-8859-1"
                                                    : "application/json");
                }
                if (mode.equals("encoding")) {
                    exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                }
                if (mode.equals("cookie2")) {
                    exchange.getResponseHeaders().set("Set-Cookie2", "SYNTHETIC_CORE_SESSION");
                }
                if (mode.equals("empty")) {
                    output = new byte[0];
                }
                exchange.sendResponseHeaders(status, mode.equals("no-entity") ? -1 : output.length);
                if (!mode.equals("no-entity")) {
                    exchange.getResponseBody().write(output);
                }
            } catch (Throwable expectedCloseOrFixtureFailure) {
                if (!(expectedCloseOrFixtureFailure instanceof java.io.IOException)) {
                    fixtureFailure.compareAndSet(null, expectedCloseOrFixtureFailure);
                }
            }
        });
        provider.createContext("/", exchange -> {
            try (exchange) {
                sends.incrementAndGet();
                providerRequest = exchange.getRequestBody().readNBytes(1_048_577);
                providerAuthorization = exchange.getRequestHeaders().getFirst("Authorization");
                providerCookie = exchange.getRequestHeaders().getFirst("Cookie");
                try {
                    providerReceivedClientIdentity = ((com.sun.net.httpserver.HttpsExchange) exchange)
                            .getSSLSession()
                            .getPeerCertificates().length > 0;
                } catch (javax.net.ssl.SSLPeerUnverifiedException noIdentity) {
                }
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(providerStatus, providerReply.length);
                exchange.getResponseBody().write(providerReply);
            } catch (Throwable expectedCloseOrFixtureFailure) {
                if (!(expectedCloseOrFixtureFailure instanceof java.io.IOException)) {
                    fixtureFailure.compareAndSet(null, expectedCloseOrFixtureFailure);
                }
            }
        });
        core.start();
        provider.start();
        var root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("coreAddress", "127.0.0.1")
                .put("certificateFile", directory.resolve("tls.crt").toString())
                .put("privateKeyFile", directory.resolve("tls.key").toString())
                .put("serverCaFile", directory.resolve("ca.pem").toString())
                .put("providerAddress", "127.0.0.1")
                .put("providerCaFile", directory.resolve("provider-ca.pem").toString())
                .put("credentialReference", "lab-key")
                .put("credentialFile", secret.toString());
        root
                .set("connection",
                        (management
                                ? GatewayManagementWireTest.consumed(managementAction)
                                : GatewayRunWireTest.consumed()).get("connection"));
        root
                .put("coreOrigin", "https://core.test:" + core.getAddress().getPort() + context)
                .put("providerOrigin", "https://provider.test:" + provider.getAddress().getPort());
        Files.write(config, JSON.writeValueAsBytes(root));
        Files.write(envelope, PROTOCOL.writeDispatch(dispatch));
        Files
                .writeString(secret,
                        "{\"protocolVersion\":1,\"credentialReference\":\"lab-key\",\"authentication\":4,\"bearer\":\""
                                + TOKEN + "\"}");
    }

    private HttpsServer server(SSLContext context, boolean clientAuth) throws Exception {
        var server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 8);
        server.setExecutor(threads);
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters p) {
                var parameters = context.getDefaultSSLParameters();
                parameters.setProtocols(new String[]{"TLSv1.3"});
                if (clientAuth) {
                    parameters.setNeedClientAuth(true);
                } else {
                    parameters.setWantClientAuth(true);
                }
                p.setSSLParameters(parameters);
            }
        });
        return server;
    }

    private record Material(KeyPair keys, X509Certificate certificate) {
    }

    private static Material material(String name, Material issuer, boolean ca, String host) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keys = generator.generateKeyPair();
        var subject = new X500Name("CN=" + name);
        var signer = issuer == null ? keys : issuer.keys;
        var issuerName = issuer == null
                ? subject
                : new X500Name(issuer.certificate.getSubjectX500Principal().getName());
        var builder = new JcaX509v3CertificateBuilder(issuerName,
                java.math.BigInteger.valueOf(Math.abs(System.nanoTime())), Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plusSeconds(3600)), subject, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (host != null) {
            builder
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
        }
        return new Material(keys, new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate()))));
    }

    private static SSLContext tls(Material identity, Material ca, Material... additionalTrust) throws Exception {
        var keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys
                .setKeyEntry("identity", identity.keys.getPrivate(), new char[0],
                        new X509Certificate[]{identity.certificate, ca.certificate});
        var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, new char[0]);
        var trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", ca.certificate);
        for (int index = 0; index < additionalTrust.length; index++) {
            trust.setCertificateEntry("extra-" + index, additionalTrust[index].certificate);
        }
        var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(trust);
        var result = SSLContext.getInstance("TLS");
        result.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        return result;
    }

    private static void pem(Path file, String label, byte[] bytes) throws Exception {
        Files
                .writeString(file,
                        "-----BEGIN " + label + "-----\n"
                                + Base64.getMimeEncoder(64, new byte[]{10}).encodeToString(bytes) + "\n-----END "
                                + label + "-----\n");
    }

    @Override
    public void close() throws Exception {
        closing = true;
        core.stop(0);
        provider.stop(0);
        threads.shutdownNow();
        if (!threads.awaitTermination(2, TimeUnit.SECONDS)) {
            throw new AssertionError("FIXTURE_OWNER_ALIVE");
        }
        if (fixtureFailure.get() != null) {
            throw new AssertionError("FIXTURE_PROTOCOL_FAILURE", fixtureFailure.get());
        }
    }
}
