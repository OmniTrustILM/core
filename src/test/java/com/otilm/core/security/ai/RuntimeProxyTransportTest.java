package com.otilm.core.security.ai;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import org.apache.catalina.Globals;
import org.apache.catalina.startup.Tomcat;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.tlsContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuntimeProxyTransportTest {
    private static final String PEER = "ilm-runtime-proxy://lab/ns/runtime/sa/runner/pod/run-a/uid/"
            + "27b7adad-1f27-490a-971d-633e8abbdfbd";
    private static final String BOOTSTRAP = "/api/internal/ai-runtime/v1/runner/bootstrap";
    private static final AtomicReference<RuntimeProxyTrustManager.Policy> POLICY = new AtomicReference<>();
    private static final AtomicInteger CALLS = new AtomicInteger();
    private static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    private static Tomcat tomcat;
    private static RuntimeProxyTransport transport;
    private static RuntimeProxyTrustManagerTest.Identity authority;
    private static RuntimeProxyTrustManagerTest.Identity runner;
    private static SSLContext clientContext;
    private static SSLContext anonymousContext;
    private static X509ExtendedKeyManager serverKeys;

    @TempDir
    static Path directory;

    @BeforeAll
    static void start() throws Exception {
        authority = issue(null, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(60), NOW.plusSeconds(900));
        runner = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, PEER)), NOW.minusSeconds(10),
                NOW.plusSeconds(600));
        var server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")), NOW.minusSeconds(10),
                NOW.plusSeconds(600));
        var trusted = KeyStore.getInstance("PKCS12");
        trusted.load(null, null);
        trusted.setCertificateEntry("authority", authority.certificate());
        var trust = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        trust.init(trusted);
        clientContext = tlsContext(runner, chain(runner, authority), trust.getTrustManagers());
        anonymousContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        anonymousContext.init(new javax.net.ssl.KeyManager[0], trust.getTrustManagers(), null);
        var keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("server", server.keys().getPrivate(), new char[0], chain(server, authority));
        var keyFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        keyFactory.init(keys, new char[0]);
        var manager = new RuntimeProxyTrustManager(POLICY::get, Clock.fixed(NOW, ZoneOffset.UTC));
        serverKeys = (X509ExtendedKeyManager) keyFactory.getKeyManagers()[0];
        transport = new RuntimeProxyTransport(InetAddress.getLoopbackAddress(), 0, "/api", serverKeys, manager);
        tomcat = new Tomcat();
        tomcat.setBaseDir(directory.toString());
        tomcat.setPort(0);
        tomcat.getConnector().setProperty("address", "127.0.0.1");
        tomcat.getService().addConnector(transport.connector());
        tomcat.getEngine().getPipeline().addValve(transport.boundary());
        var context = tomcat.addContext("/api", directory.toString());
        transport.installDispatchGuard(context);
        var error = new org.apache.tomcat.util.descriptor.web.ErrorPage();
        error.setErrorCode(500);
        error.setLocation("/error");
        context.addErrorPage(error);
        Tomcat.addServlet(context, "probe", new ProbeServlet()).setAsyncSupported(true);
        context.addServletMappingDecoded("/*", "probe");
        tomcat.start();
    }

    @AfterAll
    static void stop() throws Exception {
        if (tomcat != null) {
            try {
                tomcat.stop();
            } finally {
                tomcat.destroy();
            }
        }
    }

    @BeforeEach
    void reset() {
        POLICY.set(freshPolicy(Set.of()));
        CALLS.set(0);
    }

    @Test
    void authenticatesTheNativeTlsPeerBeforeCallingTheRuntimeRoute() {
        assertThatCode(() -> {
            try (var client = client(clientContext)) {
                var reply = send(client, true, BOOTSTRAP, "POST");
                assertThat(reply.statusCode()).isEqualTo(200);
                assertThat(reply.body()).startsWith(PEER + "\n");
                assertThat(reply.headers().firstValue("X-Probe-Async-Supported")).contains("false");
                assertThat(CALLS).hasValue(1);
            }
        }).doesNotThrowAnyException();
    }

    @Test
    void neverLetsOrdinaryConnectorHeadersGrantRuntimeAccess() throws Exception {
        try (var client = client(clientContext)) {
            var uri = URI.create("http://localhost:" + tomcat.getConnector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Forwarded-Proto", "https")
                    .header("X-Forwarded-Port", "443")
                    .header("X-Client-Cert", "untrusted-certificate-text")
                    .header("Authorization", "Bearer ignored")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
            assertThat(CALLS).hasValue(0);
            assertThat(send(client, false, "/api/ordinary", "GET").body()).isEqualTo("ordinary");
        }
    }

    @Test
    void restrictsTheRuntimeConnectorToExactPostRoutes() throws Exception {
        try (var client = client(clientContext)) {
            for (String path : List
                    .of("/api/ordinary", "/api/error", "/api/actuator/health", BOOTSTRAP + ";x=y",
                            "/api/internal/ai-runtime/v1/runner/%62ootstrap", BOOTSTRAP + "?x=y")) {
                assertThat(send(client, true, path, "POST").statusCode()).isEqualTo(403);
            }
            assertThat(send(client, true, BOOTSTRAP, "GET").statusCode()).isEqualTo(403);
            assertThat(CALLS).hasValue(0);
            assertThat(send(client, true, BOOTSTRAP, "POST").statusCode()).isEqualTo(200);
        }
    }

    @Test
    void requiresAClientCertificateBeforeCallingTheApplication() throws Exception {
        try (var socket = (javax.net.ssl.SSLSocket) anonymousContext
                .getSocketFactory()
                .createSocket("localhost", transport.connector().getLocalPort())) {
            socket.setSoTimeout(3000);
            var parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            assertThatThrownBy(() -> {
                socket.startHandshake();
                exchange(socket);
            }).isInstanceOf(javax.net.ssl.SSLException.class);
            assertThat(CALLS).hasValue(0);
        }
        try (var client = client(clientContext)) {
            assertThat(send(client, true, BOOTSTRAP, "POST").statusCode()).isEqualTo(200);
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsTls12BeforeCallingTheApplication() throws Exception {
        try (var socket = (javax.net.ssl.SSLSocket) clientContext
                .getSocketFactory()
                .createSocket("localhost", transport.connector().getLocalPort())) {
            socket.setSoTimeout(3000);
            socket.setEnabledProtocols(new String[]{"TLSv1.2"});
            var parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            assertThatThrownBy(socket::startHandshake).isInstanceOf(javax.net.ssl.SSLHandshakeException.class);
            assertThat(CALLS).hasValue(0);
        }
        try (var client = client(clientContext)) {
            assertThat(send(client, true, BOOTSTRAP, "POST").statusCode()).isEqualTo(200);
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void preservesOrdinaryErrorHandling() throws Exception {
        try (var client = client(clientContext)) {
            var reply = send(client, false, "/api/ordinary-error", "GET");
            assertThat(reply.statusCode()).isEqualTo(404);
            assertThat(reply.body()).isEqualTo("ordinary");
            assertThat(CALLS).hasValue(2);
        }
    }

    @Test
    void preservesOrdinaryAsyncProcessing() throws Exception {
        try (var client = client(clientContext)) {
            var response = send(client, false, "/api/async", "GET");
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo("ordinary");
            assertThat(response.headers().firstValue("X-Probe-Async-Supported")).contains("true");
        }
    }

    @Test
    void rejectsForwardingFromTheRuntimeConnectorIntoOrdinaryRoutes() throws Exception {
        try (var client = client(clientContext)) {
            var uri = URI.create("https://localhost:" + transport.connector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Probe-Forward", "true")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsOrdinaryConnectorForwardsIntoRuntimeRoutes() throws Exception {
        try (var client = client(clientContext)) {
            assertThat(send(client, false, "/api/forward-runtime", "GET").statusCode()).isEqualTo(403);
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void keepsRuntimeErrorsOutOfTheOrdinaryErrorHandler() throws Exception {
        try (var client = client(clientContext)) {
            var uri = URI.create("https://localhost:" + transport.connector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Probe-Error", "true")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            var reply = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(reply.statusCode()).isEqualTo(403);
            assertThat(reply.body()).doesNotContain("private-test-error-detail");
            var error = new com.fasterxml.jackson.databind.ObjectMapper().readTree(reply.body());
            assertThat(error.properties())
                    .extracting(java.util.Map.Entry::getKey)
                    .containsExactlyInAnyOrder("protocolVersion", "code", "correlationId");
            assertThat(error.get("protocolVersion").intValue()).isEqualTo(1);
            assertThat(error.get("code").textValue()).isEqualTo("DENIED");
            assertThat(java.util.UUID.fromString(error.get("correlationId").textValue())).isNotNull();
            assertThat(reply.headers().firstValue("Cache-Control")).contains("no-store");
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsOrdinaryIncludesIntoRuntimeRoutes() throws Exception {
        try (var client = client(clientContext)) {
            var reply = send(client, false, "/api/include-runtime", "GET");
            assertThat(reply.statusCode()).isEqualTo(200);
            assertThat(reply.body()).isEqualTo("include-denied");
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsNamedIncludesWithNoVerifiableTarget() throws Exception {
        try (var client = client(clientContext)) {
            var reply = send(client, false, "/api/named-include-runtime", "GET");
            assertThat(reply.statusCode()).isEqualTo(200);
            assertThat(reply.body()).isEqualTo("include-denied");
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsNamedForwardsWithNoVerifiableTarget() throws Exception {
        try (var client = client(clientContext)) {
            assertThat(send(client, false, "/api/named-forward-runtime", "GET").statusCode()).isEqualTo(403);
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void rejectsRuntimeIncludesIntoOrdinaryRoutes() throws Exception {
        try (var client = client(clientContext)) {
            var uri = URI.create("https://localhost:" + transport.connector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Probe-Include", "true")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            var reply = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(reply.statusCode()).isEqualTo(200);
            assertThat(reply.body()).isEqualTo("include-denied");
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void refusesMismatchedAndRepeatedDispatchGuardInstallation() {
        var wrong = new org.apache.catalina.core.StandardContext();
        wrong.setPath("/another");
        assertThatThrownBy(() -> transport.installDispatchGuard(wrong)).isInstanceOf(IllegalArgumentException.class);
        assertThat(wrong.findFilterDefs()).isEmpty();
        var matching = (org.apache.catalina.Context) tomcat.getHost().findChild("/api");
        var installed = matching.findFilterDef(RuntimeProxyDispatchFilter.class.getName());
        assertThatThrownBy(() -> transport.installDispatchGuard(matching)).isInstanceOf(IllegalArgumentException.class);
        assertThat(matching.findFilterDefs()).containsExactly(installed);
    }

    @Test
    void refusesLateDispatchGuardInstallationAndKeepsTheListenerClosed() throws Exception {
        var late = new RuntimeProxyTransport(InetAddress.getLoopbackAddress(), 0, "/api", serverKeys,
                new RuntimeProxyTrustManager(POLICY::get, Clock.fixed(NOW, ZoneOffset.UTC)));
        var server = new Tomcat();
        server.setBaseDir(directory.resolve("late").toString());
        server.setPort(0);
        server.getConnector().setProperty("address", "127.0.0.1");
        server.getService().addConnector(late.connector());
        server.getEngine().getPipeline().addValve(late.boundary());
        var context = server.addContext("/api", directory.toString());
        Tomcat.addServlet(context, "late-probe", new ProbeServlet());
        context.addServletMappingDecoded("/*", "late-probe");
        try {
            server.start();
            var failure = org.assertj.core.api.Assertions.catchThrowable(() -> late.installDispatchGuard(context));
            try (var client = client(clientContext)) {
                var request = HttpRequest
                        .newBuilder(URI.create("https://localhost:" + late.connector().getLocalPort() + BOOTSTRAP))
                        .timeout(Duration.ofSeconds(3))
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build();
                var reply = client.send(request, HttpResponse.BodyHandlers.ofString());
                org.junit.jupiter.api.Assertions
                        .assertAll(() -> assertThat(failure).isInstanceOf(IllegalArgumentException.class),
                                () -> assertThat(reply.statusCode()).isEqualTo(403),
                                () -> assertThat(CALLS).hasValue(0));
            }
        } finally {
            try {
                server.stop();
            } finally {
                server.destroy();
            }
        }
    }

    @Test
    void refusesAnEarlierBeforeFilterMappingWithoutBindingTheGuard() throws Exception {
        var candidate = new RuntimeProxyTransport(InetAddress.getLoopbackAddress(), 0, "/api", serverKeys,
                new RuntimeProxyTrustManager(POLICY::get, Clock.fixed(NOW, ZoneOffset.UTC)));
        var context = new org.apache.catalina.core.StandardContext();
        context.setPath("/api");
        var definition = new org.apache.tomcat.util.descriptor.web.FilterDef();
        definition.setFilterName("earlier");
        definition.setFilter((request, response, chain) -> chain.doFilter(request, response));
        context.addFilterDef(definition);
        var mapping = new org.apache.tomcat.util.descriptor.web.FilterMap();
        mapping.setFilterName("earlier");
        mapping.addURLPattern("/*");
        context.addFilterMapBefore(mapping);
        attachEngineBoundary(candidate, context);
        assertThatThrownBy(() -> candidate.installDispatchGuard(context)).isInstanceOf(IllegalArgumentException.class);
        assertThat(((RuntimeProxyBoundaryValve) candidate.boundary()).guardInstalled()).isFalse();
    }

    @Test
    void leavesTheListenerClosedWhenDispatchRegistrationFails() throws Exception {
        var candidate = new RuntimeProxyTransport(InetAddress.getLoopbackAddress(), 0, "/api", serverKeys,
                new RuntimeProxyTrustManager(POLICY::get, Clock.fixed(NOW, ZoneOffset.UTC)));
        var context = new org.apache.catalina.core.StandardContext() {
            @Override
            public void addFilterMapBefore(org.apache.tomcat.util.descriptor.web.FilterMap mapping) {
                throw new IllegalArgumentException("Synthetic registration failure");
            }
        };
        context.setPath("/api");
        attachEngineBoundary(candidate, context);
        assertThatThrownBy(() -> candidate.installDispatchGuard(context)).isInstanceOf(IllegalArgumentException.class);
        assertThat(((RuntimeProxyBoundaryValve) candidate.boundary()).guardInstalled()).isFalse();
        assertThatThrownBy(() -> candidate.installDispatchGuard(context)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "forward,/internal/%61i-runtime/v1/runner/bootstrap",
            "forward,/internal;x=y/ai-runtime/v1/runner/bootstrap",
            "include,/internal/%61i-runtime/v1/runner/bootstrap",
            "include,/internal;x=y/ai-runtime/v1/runner/bootstrap",
            "async,/internal/%61i-runtime/v1/runner/bootstrap",
            "async,/internal;x=y/ai-runtime/v1/runner/bootstrap"})
    void rejectsEncodedOrdinaryDispatchesIntoRuntimeRoutes(String mode, String target) throws Exception {
        try (var client = client(clientContext)) {
            var uri = URI
                    .create("http://localhost:" + tomcat.getConnector().getLocalPort() + "/api/" + mode + "-runtime");
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Probe-Target", target)
                    .GET()
                    .build();
            var reply = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (mode.equals("include")) {
                assertThat(reply.statusCode()).isEqualTo(200);
                assertThat(reply.body()).isEqualTo("include-denied");
            } else {
                assertThat(reply.statusCode()).isEqualTo(403);
            }
            assertThat(CALLS).hasValue(1);
        }
    }

    @Test
    void deniesARequestMappedToAnUnregisteredNestedContext() throws Exception {
        try (var client = client(clientContext)) {
            assertThat(send(client, true, BOOTSTRAP, "POST").statusCode()).isEqualTo(200);
            var nested = tomcat.addContext("/api/internal", directory.toString());
            try {
                Tomcat.addServlet(nested, "nested-probe", new ProbeServlet());
                nested.addServletMappingDecoded("/*", "nested-probe");
                assertThat(nested.getState().isAvailable()).isTrue();
                assertThat(send(client, true, BOOTSTRAP, "POST").statusCode()).isEqualTo(403);
                assertThat(CALLS).hasValue(1);
            } finally {
                tomcat.getHost().removeChild(nested);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"404", "exception"})
    void keepsUnmappedRuntimeErrorsClosed(String kind) throws Exception {
        var context = (org.apache.catalina.Context) tomcat.getHost().findChild("/api");
        var old = context.findErrorPage(500);
        context.removeErrorPage(old);
        try (var client = client(clientContext)) {
            var uri = URI.create("https://localhost:" + transport.connector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(3))
                    .header("X-Probe-Unmapped-Error", kind)
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            var reply = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(reply.statusCode()).isEqualTo(403);
            assertThat(reply.body()).doesNotContain("private-test-error-detail");
            assertThat(CALLS).hasValue(1);
        } finally {
            context.addErrorPage(old);
        }
    }

    @Test
    void rechecksCurrentTrustOnTheSameKeptAliveConnection() throws Exception {
        try (var socket = (javax.net.ssl.SSLSocket) clientContext
                .getSocketFactory()
                .createSocket("localhost", transport.connector().getLocalPort())) {
            socket.setSoTimeout(3000);
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            var parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            String accepted = exchange(socket).body();
            assertThat(accepted).startsWith(PEER + "\n");
            POLICY.set(null);
            assertThat(exchange(socket).status()).isEqualTo(403);
            assertThat(CALLS).hasValue(1);
            POLICY.set(freshPolicy(Set.of()));
            assertThat(exchange(socket).body()).isEqualTo(accepted);
            assertThat(CALLS).hasValue(2);
        }
    }

    @Test
    void hidesPolicySourceFailuresDuringNativeChainCompletion() {
        var lookups = new AtomicInteger();
        var trust = new RuntimeProxyTrustManager(() -> {
            if (lookups.incrementAndGet() == 1) {
                return freshPolicy(Set.of());
            }
            throw new IllegalStateException("private-policy-source-detail");
        }, Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> trust.verifyNativeChain(chain(runner, authority)))
                .isInstanceOf(java.security.cert.CertificateException.class)
                .hasMessage("Runtime proxy certificate rejected")
                .hasNoCause();
    }

    @ParameterizedTest
    @EnumSource(TrustChange.class)
    void deniesChangedTrustOnAnAlreadyEstablishedSocket(TrustChange change) throws Exception {
        try (var socket = (javax.net.ssl.SSLSocket) clientContext
                .getSocketFactory()
                .createSocket("localhost", transport.connector().getLocalPort())) {
            socket.setSoTimeout(3000);
            socket.startHandshake();
            assertThat(exchange(socket).status()).isEqualTo(200);
            var authorities = List.of(new RuntimeProxyTrustManager.Authority("lab", authority.certificate()));
            Set<String> denied = Set.of();
            Instant observed = NOW;
            Instant expires = NOW.plusSeconds(30);
            switch (change) {
                case DENIED_LEAF -> denied = Set
                        .of(java.util.HexFormat
                                .of()
                                .formatHex(java.security.MessageDigest
                                        .getInstance("SHA-256")
                                        .digest(runner.certificate().getTBSCertificate())));
                case REMOVED_AUTHORITY ->
                    authorities = List.of(new RuntimeProxyTrustManager.Authority("foreign", authority.certificate()));
                case EXPIRED -> {
                    observed = NOW.minusSeconds(30);
                    expires = NOW;
                }
                case FUTURE -> observed = NOW.plusSeconds(1);
            }
            POLICY.set(new RuntimeProxyTrustManager.Policy(authorities, denied, observed, expires));
            assertThat(exchange(socket).status()).isEqualTo(403);
            assertThat(CALLS).hasValue(1);
            POLICY.set(freshPolicy(Set.of()));
            assertThat(exchange(socket).status()).isEqualTo(200);
            assertThat(CALLS).hasValue(2);
        }
    }

    @Test
    void rejectsInvalidTransportConfigurationBeforeOpeningAListener() {
        var trust = new RuntimeProxyTrustManager(POLICY::get, Clock.fixed(NOW, ZoneOffset.UTC));
        var address = InetAddress.getLoopbackAddress();
        for (String context : List.of("/api/", "/api//internal", "/api/../internal", "api", "/a".repeat(65))) {
            assertThatThrownBy(() -> new RuntimeProxyTransport(address, 0, context, serverKeys, trust))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        for (int port : List.of(-1, 65536)) {
            assertThatThrownBy(() -> new RuntimeProxyTransport(address, port, "/api", serverKeys, trust))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new RuntimeProxyTransport(address, 0, null, serverKeys, trust))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyTransport(null, 0, "/api", serverKeys, trust))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RuntimeProxyTransport(address, 0, "/api", null, trust))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RuntimeProxyTransport(address, 0, "/api", serverKeys, null))
                .isInstanceOf(NullPointerException.class);
    }

    private enum TrustChange {
        DENIED_LEAF,
        REMOVED_AUTHORITY,
        EXPIRED,
        FUTURE
    }

    private static WireReply exchange(javax.net.ssl.SSLSocket socket) throws IOException {
        var output = socket.getOutputStream();
        output
                .write(("POST " + BOOTSTRAP + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n"
                        + "Connection: keep-alive\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        output.flush();
        var input = socket.getInputStream();
        var headers = new java.io.ByteArrayOutputStream();
        String text;
        do {
            int next = input.read();
            if (next < 0 || headers.size() >= 8192) {
                throw new IOException("Incomplete test HTTP response");
            }
            headers.write(next);
            text = headers.toString(StandardCharsets.US_ASCII);
        } while (!text.endsWith("\r\n\r\n"));
        var lines = text.split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        int length = -1;
        for (String line : lines) {
            if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                length = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
            }
        }
        if (length < 0 || length > 4096) {
            throw new IOException("Unbounded test HTTP response");
        }
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) {
            throw new IOException("Truncated test HTTP response");
        }
        return new WireReply(status, new String(bytes, StandardCharsets.UTF_8));
    }

    private record WireReply(int status, String body) {
    }

    private static void attachEngineBoundary(RuntimeProxyTransport candidate, org.apache.catalina.Context context) {
        var engine = new org.apache.catalina.core.StandardEngine();
        var host = new org.apache.catalina.core.StandardHost();
        host.setName("localhost");
        engine.addChild(host);
        host.addChild(context);
        engine.getPipeline().addValve(candidate.boundary());
    }

    private static HttpClient client(SSLContext tls) {
        return HttpClient
                .newBuilder()
                .sslContext(tls)
                .connectTimeout(Duration.ofSeconds(2))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    private static HttpResponse<String> send(HttpClient client, boolean runtime, String path, String method)
            throws Exception {
        int port = runtime ? transport.connector().getLocalPort() : tomcat.getConnector().getLocalPort();
        var uri = URI.create((runtime ? "https" : "http") + "://localhost:" + port + path);
        var request = HttpRequest
                .newBuilder(uri)
                .timeout(Duration.ofSeconds(3))
                .method(method, HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static RuntimeProxyTrustManager.Policy freshPolicy(Set<String> denied) {
        return new RuntimeProxyTrustManager.Policy(
                List.of(new RuntimeProxyTrustManager.Authority("lab", authority.certificate())), denied, NOW,
                NOW.plusSeconds(30));
    }

    private static final class ProbeServlet extends HttpServlet {
        @Override
        protected void service(HttpServletRequest request, HttpServletResponse response)
                throws IOException, jakarta.servlet.ServletException {
            CALLS.incrementAndGet();
            request.getInputStream().readNBytes(128);
            if (request.getRequestURI().equals("/api/ordinary-error")) {
                response.sendError(404, "ordinary-test-error");
                return;
            }
            if (request.getRequestURI().equals(BOOTSTRAP) && request.getHeader("X-Probe-Unmapped-Error") != null) {
                if (request.getHeader("X-Probe-Unmapped-Error").equals("exception")) {
                    throw new jakarta.servlet.ServletException("private-test-error-detail");
                }
                response.sendError(404, "private-test-error-detail");
                return;
            }
            if (request.getRequestURI().equals(BOOTSTRAP) && request.getHeader("X-Probe-Error") != null) {
                response.sendError(500, "private-test-error-detail");
                return;
            }
            if (request.getRequestURI().equals(BOOTSTRAP) && request.getHeader("X-Probe-Forward") != null) {
                request.getRequestDispatcher("/ordinary").forward(request, response);
                return;
            }
            if (request.getRequestURI().equals("/api/forward-runtime")) {
                request.getRequestDispatcher(target(request)).forward(request, response);
                return;
            }
            if (request.getDispatcherType() == jakarta.servlet.DispatcherType.REQUEST
                    && request.getRequestURI().equals("/api/named-forward-runtime")) {
                request.getServletContext().getNamedDispatcher("probe").forward(request, response);
                return;
            }
            if (request.getDispatcherType() == jakarta.servlet.DispatcherType.REQUEST
                    && request.getRequestURI().equals("/api/async-runtime")) {
                request.startAsync().dispatch(target(request));
                return;
            }
            if (request.getDispatcherType() == jakarta.servlet.DispatcherType.REQUEST
                    && (request.getRequestURI().equals("/api/include-runtime")
                            || request.getRequestURI().equals("/api/named-include-runtime")
                            || request.getRequestURI().equals(BOOTSTRAP)
                                    && request.getHeader("X-Probe-Include") != null)) {
                String target = request.getRequestURI().equals(BOOTSTRAP) ? "/ordinary" : target(request);
                try {
                    var dispatcher = request.getRequestURI().equals("/api/named-include-runtime")
                            ? request.getServletContext().getNamedDispatcher("probe")
                            : request.getRequestDispatcher(target);
                    dispatcher.include(request, response);
                } catch (jakarta.servlet.ServletException rejected) {
                    write(response, "include-denied");
                    return;
                }
                write(response, "include-was-allowed");
                return;
            }
            var async = request.getRequestURI().equals("/api/async") ? request.startAsync() : null;
            response.setHeader("X-Probe-Async-Supported", Boolean.toString(request.isAsyncSupported()));
            var peer = RuntimeProxyTransport.currentPeer();
            write(response,
                    peer
                            .map(value -> value.uri() + "\n" + request.getAttribute(Globals.SSL_SESSION_ID_ATTR))
                            .orElse("ordinary"));
            if (async != null) {
                async.complete();
            }
        }

        private static void write(HttpServletResponse response, String text) throws IOException {
            byte[] body = text.getBytes(StandardCharsets.UTF_8);
            response.setContentType("text/plain");
            response.setContentLength(body.length);
            response.getOutputStream().write(body);
        }

        private static String target(HttpServletRequest request) {
            String selected = request.getHeader("X-Probe-Target");
            return selected == null ? "/internal/ai-runtime/v1/runner/bootstrap" : selected;
        }
    }
}
