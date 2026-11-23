package com.otilm.core.security.ai;

import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeRunnerServiceImpl;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import org.apache.catalina.Lifecycle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.tlsContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RuntimeProxyTomcatBindingTest {
    private static final String BOOTSTRAP = "/api/internal/ai-runtime/v1/runner/bootstrap";
    private static final RuntimeProxyCertificateClaims SUBJECT = RuntimeProxyCertificateClaims
            .parse("ilm-runtime-proxy://lab/ns/runtime/sa/runner/pod/run-a/uid/27b7adad-1f27-490a-971d-633e8abbdfbd")
            .orElseThrow();
    private final List<TomcatWebServer> servers = new ArrayList<>();
    private final List<RuntimeProxyTomcatBinding> bindings = new ArrayList<>();
    @TempDir
    Path directory;
    private X509ExtendedKeyManager keys;
    private RuntimeProxyTrustManager.Policy policy;
    private SSLContext client;
    private Clock clock;

    @BeforeEach
    void certificates() throws Exception {
        Instant now = Instant.now();
        clock = Clock.fixed(now, ZoneOffset.UTC);
        var authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(30), now.plusSeconds(900));
        var server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.iPAddress, "127.0.0.1")), now.minusSeconds(10),
                now.plusSeconds(600));
        var caller = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                        RuntimePeerRole.RUNNER_PROXY.certificateUri(SUBJECT))),
                now.minusSeconds(10), now.plusSeconds(600));
        var roots = KeyStore.getInstance("PKCS12");
        roots.load(null, null);
        roots.setCertificateEntry("authority", authority.certificate());
        var trusted = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        trusted.init(roots);
        client = tlsContext(caller, chain(caller, authority), trusted.getTrustManagers());
        var store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("server", server.keys().getPrivate(), new char[0], chain(server, authority));
        var factory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        factory.init(store, new char[0]);
        keys = (X509ExtendedKeyManager) factory.getKeyManagers()[0];
        policy = new RuntimeProxyTrustManager.Policy(RuntimeProxyTrustManagerTest.authorities(authority.certificate()),
                Set.of(), now, now.plusSeconds(30));
    }

    @AfterEach
    void cleanup() {
        bindings.forEach(RuntimeProxyTomcatBinding::close);
        for (var server : servers) {
            try {
                server.stop();
            } finally {
                server.destroy();
            }
        }
    }

    @Test
    void nativePortsAttachAfterOrdinaryBootAndCloseWithoutStoppingIt() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding);
        assertThat(transport.connector().getLocalPort()).isNegative();
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");

        assertThat(binding.start(server)).isTrue();
        assertThat(binding.start(server)).isTrue();
        int port = transport.connector().getLocalPort();
        assertThat(port).isPositive();
        assertThat(nativePost(port).body()).isEqualTo("RUNNER_PROXY");
        assertThat(ordinaryStatus(server, BOOTSTRAP.substring(4))).isEqualTo(403);
        binding.close();
        binding.close();

        assertThat(binding.listenersStarted()).isFalse();
        assertThatThrownBy(() -> nativePost(port)).isInstanceOf(IOException.class);
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
        assertThat(binding.start(server)).isFalse();
    }

    @Test
    void partialNativeBindFailureClosesStartedPortsAndPreservesOrdinaryServer() throws Exception {
        try (var occupied = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            var transport = transport(occupied.getLocalPort());
            var firstPort = new AtomicInteger();
            transport.connectors().get(RuntimePeerRole.RUNNER_PROXY).addLifecycleListener(event -> {
                if (Lifecycle.AFTER_START_EVENT.equals(event.getType())) {
                    firstPort.set(transport.connectors().get(RuntimePeerRole.RUNNER_PROXY).getLocalPort());
                }
            });
            var binding = binding(transport);
            var server = ordinary(binding);

            assertThat(binding.start(server)).isFalse();

            assertThat(firstPort).hasPositiveValue();
            assertThat(binding.listenersStarted()).isFalse();
            assertThat(transport.connectors().values())
                    .allSatisfy(connector -> assertThat(connector.getState().isAvailable()).isFalse());
            assertThatThrownBy(() -> nativePost(firstPort.get())).isInstanceOf(IOException.class);
            assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
            assertThat(binding.start(server)).isFalse();
        }
    }

    @Test
    void anotherBootServerCannotOwnTheConfiguredBoundary() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var first = ordinary(binding);
        var other = ordinary(null);

        assertThat(binding.start(other)).isFalse();

        assertThat(transport.connector().getLocalPort()).isNegative();
        assertThat(ordinaryGet(first, "/ordinary")).isEqualTo("ordinary");
        assertThat(ordinaryGet(other, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void aBindingCanConfigureOnlyOneFactory() throws Exception {
        var binding = binding(transport(-1));
        var first = factory();
        binding.configure(first);
        var other = factory();

        assertThatThrownBy(() -> binding.configure(other)).isInstanceOf(IllegalStateException.class);
        assertThat(other.getEngineValves()).isEmpty();
        assertThat(other.getContextCustomizers()).isEmpty();
    }

    @Test
    void anUnconfiguredBindingCannotStartNativePorts() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(null);

        assertThat(binding.start(server)).isFalse();

        assertThat(transport.connector().getLocalPort()).isNegative();
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void disabledNativeTransportDeniesAnEstablishedConnectionWithoutChangingOrdinaryAccess() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding);
        assertThat(binding.start(server)).isTrue();
        try (var http = HttpClient.newBuilder().sslContext(client).build()) {
            var uri = URI.create("https://127.0.0.1:" + transport.connector().getLocalPort() + BOOTSTRAP);
            var request = HttpRequest
                    .newBuilder(uri)
                    .timeout(Duration.ofSeconds(2))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
            transport.disable();
            assertThat(binding.listenersStarted()).isFalse();
            assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
        }
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void aConfiguredBindingCannotAttachBeforeOrdinaryBootFinishes() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var factory = factory();
        binding.configure(factory);
        var server = (TomcatWebServer) factory
                .getWebServer(context -> context.addServlet("probe", new ProbeServlet()).addMapping("/*"));
        servers.add(server);

        assertThat(binding.start(server)).isFalse();
        server.start();

        assertThat(binding.start(server)).isFalse();
        assertThat(transport.connector().getLocalPort()).isNegative();
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void aDisabledTransportCannotBeRestartedByStartingItsBinding() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding);
        transport.disable();

        assertThat(binding.start(server)).isFalse();

        assertThat(transport.connector().getLocalPort()).isNegative();
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void unavailableServerMetadataFailsClosedWithoutStoppingTheOrdinaryServer() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding);
        var faulty = org.mockito.Mockito.spy(server);
        org.mockito.Mockito.doThrow(new IllegalStateException("synthetic-lifecycle-failure")).when(faulty).getTomcat();

        assertThat(binding.start(faulty)).isFalse();

        assertThat(transport.disabled()).isTrue();
        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
    }

    @Test
    void oneNativeStopFailureStillFencesAllRolesAndClosesTheOtherNativePort() throws Exception {
        var transport = transport(0);
        var binding = binding(transport);
        var server = ordinary(binding);
        assertThat(binding.start(server)).isTrue();
        var runner = transport.connectors().get(RuntimePeerRole.RUNNER_PROXY);
        var controller = transport.connectors().get(RuntimePeerRole.CONTROLLER);
        assertThat(nativePost(runner.getLocalPort()).statusCode()).isEqualTo(200);
        org.apache.catalina.LifecycleListener failure = event -> {
            if (Lifecycle.BEFORE_STOP_EVENT.equals(event.getType())) {
                throw new IllegalStateException("synthetic-native-stop-failure");
            }
        };
        runner.addLifecycleListener(failure);
        try {
            binding.close();
            assertThat(binding.listenersStarted()).isFalse();
            assertThat(transport.disabled()).isTrue();
            assertThat(controller.getState()).isEqualTo(org.apache.catalina.LifecycleState.DESTROYED);
            assertThat(controller.getLocalPort()).isNegative();
            assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
        } finally {
            runner.removeLifecycleListener(failure);
            binding.close();
        }
    }

    @Test
    void closingBeforeFactoryCreationStillAllowsOrdinaryBootWithReservedRoutesDenied() throws Exception {
        var binding = binding(transport(-1));
        var factory = factory();
        binding.configure(factory);
        binding.close();
        var server = (TomcatWebServer) factory
                .getWebServer(context -> context.addServlet("probe", new ProbeServlet()).addMapping("/*"));
        servers.add(server);
        server.start();

        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
        assertThat(ordinaryStatus(server, BOOTSTRAP.substring(4))).isEqualTo(403);
        assertThat(binding.start(server)).isFalse();
    }

    @Test
    void rejectedEarlyStartStillAllowsTheConfiguredFactoryToBootOrdinaryCore() throws Exception {
        var binding = binding(transport(-1));
        var factory = factory();
        binding.configure(factory);
        assertThat(binding.start(null)).isFalse();
        var server = (TomcatWebServer) factory
                .getWebServer(context -> context.addServlet("probe", new ProbeServlet()).addMapping("/*"));
        servers.add(server);
        server.start();

        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
        assertThat(ordinaryStatus(server, BOOTSTRAP.substring(4))).isEqualTo(403);
        assertThat(binding.start(server)).isFalse();
    }

    @Test
    void closingAfterBootStopPreservesOrdinaryRestartAndNativeDenial() throws Exception {
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding);
        assertThat(binding.start(server)).isTrue();
        server.stop();
        binding.close();
        server.start();

        assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
        assertThat(ordinaryStatus(server, BOOTSTRAP.substring(4))).isEqualTo(403);
        assertThat(binding.listenersStarted()).isFalse();
        assertThat(transport.disabled()).isTrue();
        assertThat(transport.connector().getLocalPort()).isPositive();
        try (var http = HttpClient.newBuilder().sslContext(client).build()) {
            var request = HttpRequest
                    .newBuilder(URI.create("https://127.0.0.1:" + transport.connector().getLocalPort() + BOOTSTRAP))
                    .timeout(Duration.ofSeconds(2))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
        }
    }

    @Test
    void aCompleteNativeBodyReachesTheCanonicalRequestParserAndCurrentRunLookup() throws Exception {
        var kernel = mock(AiRuntimeKernel.class);
        var auth = mock(PlatformAuthenticationClient.class);
        var runner = new AiRuntimeRunnerServiceImpl(kernel, auth, new AiFeatureGate(true));
        var runId = UUID.randomUUID();
        when(kernel
                .snapshot(org.mockito.ArgumentMatchers.eq(runId),
                        org.mockito.ArgumentMatchers.any(com.otilm.core.service.ai.AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.empty());
        byte[] input = new ProtocolCodec()
                .writeBootstrapRequest(new BootstrapRequest(1, runId, UUID.randomUUID(), SUBJECT.podUid()));
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding, new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
                var value = runner.bootstrap(request.getInputStream());
                response.setStatus(value.getStatusCode().value());
                response.getOutputStream().write(value.getBody());
            }
        });
        assertThat(binding.start(server)).isTrue();
        try (var http = HttpClient.newBuilder().sslContext(client).build()) {
            var request = HttpRequest
                    .newBuilder(URI.create("https://127.0.0.1:" + transport.connector().getLocalPort() + BOOTSTRAP))
                    .timeout(Duration.ofSeconds(2))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(input))
                    .build();
            var response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            assertThat(response.statusCode()).isEqualTo(503);
            assertThat(new String(response.body(), StandardCharsets.UTF_8)).contains("UNAVAILABLE");
        }
        verify(kernel)
                .snapshot(org.mockito.ArgumentMatchers.eq(runId),
                        org.mockito.ArgumentMatchers.any(com.otilm.core.service.ai.AiRuntimeOperationBudget.class));
        verifyNoInteractions(auth);
    }

    @Test
    void aDribblingNativeBodyReleasesItsHandlerWithinTheOperationAndReadCleanupBudget() throws Exception {
        var kernel = mock(AiRuntimeKernel.class);
        var auth = mock(PlatformAuthenticationClient.class);
        var runner = new AiRuntimeRunnerServiceImpl(kernel, auth, new AiFeatureGate(true));
        var entered = new CountDownLatch(1);
        var returned = new CountDownLatch(1);
        var reply = new AtomicReference<ResponseEntity<byte[]>>();
        var started = new AtomicLong();
        var transport = transport(-1);
        var binding = binding(transport);
        var server = ordinary(binding, new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
                response.getWriter().write("ordinary");
            }

            @Override
            protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
                started.set(System.nanoTime());
                entered.countDown();
                try {
                    var value = runner.bootstrap(request.getInputStream());
                    reply.set(value);
                    response.setStatus(value.getStatusCode().value());
                    response.getOutputStream().write(value.getBody());
                } finally {
                    returned.countDown();
                }
            }
        });
        assertThat(binding.start(server)).isTrue();
        try (var socket = (SSLSocket) client
                .getSocketFactory()
                .createSocket("127.0.0.1", transport.connector().getLocalPort())) {
            socket.setSoTimeout(12_000);
            socket.startHandshake();
            var output = socket.getOutputStream();
            output
                    .write(("POST " + BOOTSTRAP + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            + "Content-Length: 1024\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            output.flush();
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            try {
                for (int index = 0; index < 16; index++) {
                    output.write('{');
                    output.flush();
                    Thread.sleep(250);
                }
                assertThat(returned.getCount()).as("The incomplete body is still being read").isEqualTo(1);
                long remaining = TimeUnit.SECONDS.toNanos(6) - (System.nanoTime() - started.get());
                assertThat(remaining).isPositive();
                assertThat(returned.await(remaining, TimeUnit.NANOSECONDS))
                        .as("A native request must release its handler within five seconds plus one read-cleanup second")
                        .isTrue();
                assertThat(reply.get()).isNotNull();
                assertThat(reply.get().getStatusCode().value()).isEqualTo(503);
                verifyNoInteractions(kernel, auth);
                assertThat(ordinaryGet(server, "/ordinary")).isEqualTo("ordinary");
            } finally {
                socket.close();
                assertThat(returned.await(2, TimeUnit.SECONDS)).as("Owned handler closed after the socket").isTrue();
            }
        }
    }

    RuntimeProxyTransport transport(int controllerPort) throws Exception {
        var listeners = new ArrayList<RuntimeProxyTransport.Listener>();
        listeners
                .add(new RuntimeProxyTransport.Listener(RuntimePeerRole.RUNNER_PROXY,
                        InetAddress.getByName("127.0.0.1"), 0, keys,
                        new RuntimeProxyTrustManager(() -> policy, clock, RuntimePeerRole.RUNNER_PROXY)));
        if (controllerPort >= 0) {
            listeners
                    .add(new RuntimeProxyTransport.Listener(RuntimePeerRole.CONTROLLER,
                            InetAddress.getByName("127.0.0.1"), controllerPort, keys,
                            new RuntimeProxyTrustManager(() -> policy, clock, RuntimePeerRole.CONTROLLER)));
        }
        return RuntimeProxyTransport.forListeners("/api", listeners);
    }

    private RuntimeProxyTomcatBinding binding(RuntimeProxyTransport transport) {
        var value = new RuntimeProxyTomcatBinding(transport);
        bindings.add(value);
        return value;
    }

    TomcatServletWebServerFactory factory() throws Exception {
        var factory = new TomcatServletWebServerFactory("/api", 0);
        factory
                .setBaseDirectory(
                        java.nio.file.Files.createDirectory(directory.resolve("server-" + UUID.randomUUID())).toFile());
        var address = InetAddress.getByName("127.0.0.1");
        factory
                .addConnectorCustomizers(
                        connector -> ((org.apache.coyote.http11.Http11NioProtocol) connector.getProtocolHandler())
                                .setAddress(address));
        return factory;
    }

    private TomcatWebServer ordinary(RuntimeProxyTomcatBinding binding) throws Exception {
        return ordinary(binding, new ProbeServlet());
    }

    private TomcatWebServer ordinary(RuntimeProxyTomcatBinding binding, HttpServlet probe) throws Exception {
        var factory = factory();
        if (binding != null) {
            binding.configure(factory);
        }
        var server = (TomcatWebServer) factory.getWebServer(context -> {
            var servlet = context.addServlet("probe", probe);
            servlet.setAsyncSupported(false);
            servlet.addMapping("/*");
        });
        servers.add(server);
        server.start();
        return server;
    }

    private String ordinaryGet(TomcatWebServer server, String path) throws Exception {
        try (var http = HttpClient.newHttpClient()) {
            return http
                    .send(HttpRequest
                            .newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + "/api" + path))
                            .timeout(Duration.ofSeconds(2))
                            .GET()
                            .build(), HttpResponse.BodyHandlers.ofString())
                    .body();
        }
    }

    private int ordinaryStatus(TomcatWebServer server, String path) throws Exception {
        try (var http = HttpClient.newHttpClient()) {
            return http
                    .send(HttpRequest
                            .newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + "/api" + path))
                            .timeout(Duration.ofSeconds(2))
                            .GET()
                            .build(), HttpResponse.BodyHandlers.ofString())
                    .statusCode();
        }
    }

    HttpResponse<String> nativePost(int port) throws Exception {
        try (var http = HttpClient.newBuilder().sslContext(client).build()) {
            return http
                    .send(HttpRequest
                            .newBuilder(URI.create("https://127.0.0.1:" + port + BOOTSTRAP))
                            .timeout(Duration.ofSeconds(2))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    private static final class ProbeServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.getWriter().write("ordinary");
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.getWriter().write(RuntimeProxyTransport.currentWorkloadPeer().orElseThrow().role().name());
        }
    }
}
