package com.otilm.core.security.ai;

import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiModelManagementDispatchService;
import com.otilm.core.service.ai.AiModelRunDispatchService;
import com.otilm.core.service.ai.AiRuntimeGatewayServiceImpl;
import com.otilm.core.service.ai.AiRuntimeManagementGatewayServiceImpl;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
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
import org.junit.jupiter.params.provider.EnumSource;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.tlsContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RuntimeMultiListenerTransportTest {
    private static final String RUNNER = "/api/internal/ai-runtime/v1/runner/bootstrap";
    private static final String CONTROLLER = "/api/internal/ai-runtime/v1/controller/workloads/register";
    private static final String RUN_GATEWAY = "/api/internal/ai-runtime/v1/gateway/run/redeem";
    private static final String MANAGEMENT_GATEWAY = "/api/internal/ai-management/v1/gateway/redeem";
    private static final Map<RuntimePeerRole, String> ROUTES = Map
            .of(RuntimePeerRole.RUNNER_PROXY, RUNNER, RuntimePeerRole.CONTROLLER, CONTROLLER,
                    RuntimePeerRole.GATEWAY_RUN, RUN_GATEWAY, RuntimePeerRole.GATEWAY_MANAGEMENT, MANAGEMENT_GATEWAY);
    private static final Map<RuntimePeerRole, String> REGISTRATIONS = Map
            .of(RuntimePeerRole.GATEWAY_RUN, "/api/internal/ai-runtime/v1/gateway/run/registration",
                    RuntimePeerRole.GATEWAY_MANAGEMENT, "/api/internal/ai-management/v1/gateway/registration");
    private static AiRuntimeGatewayRegistrationWriter runRegistrations;
    private static AiRuntimeManagementGatewayWriter managementRegistrations;
    private static AiModelRunDispatchService runDispatch;
    private static AiModelManagementDispatchService managementDispatch;
    private static AiModelRunOutcomeWriter runOutcomes;
    private static AiModelManagementGatewayWriter managementAssignments;
    private static AiModelManagementOutcomeWriter managementOutcomes;
    private static AiRuntimeGatewayServiceImpl runService;
    private static AiRuntimeManagementGatewayServiceImpl managementService;
    private static final RuntimeProxyCertificateClaims SUBJECT = RuntimeProxyCertificateClaims
            .parse("ilm-runtime-proxy://lab/ns/runtime/sa/runner/pod/run-a/uid/27b7adad-1f27-490a-971d-633e8abbdfbd")
            .orElseThrow();
    private static final Map<RuntimePeerRole, SSLContext> CLIENTS = new EnumMap<>(RuntimePeerRole.class);
    private static final AtomicInteger CALLS = new AtomicInteger();
    private static RuntimeProxyTransport transport;
    private static List<RuntimeProxyTransport.Listener> listeners;
    private static Tomcat tomcat;
    @TempDir
    static Path directory;

    @BeforeAll
    static void start() throws Exception {
        runRegistrations = mock(AiRuntimeGatewayRegistrationWriter.class);
        managementRegistrations = mock(AiRuntimeManagementGatewayWriter.class);
        runDispatch = mock(AiModelRunDispatchService.class);
        managementDispatch = mock(AiModelManagementDispatchService.class);
        runOutcomes = mock(AiModelRunOutcomeWriter.class);
        managementAssignments = mock(AiModelManagementGatewayWriter.class);
        managementOutcomes = mock(AiModelManagementOutcomeWriter.class);
        when(runRegistrations.current(any(), any())).thenReturn(Optional.empty());
        when(managementRegistrations.current(any(), any())).thenReturn(Optional.empty());
        runService = new AiRuntimeGatewayServiceImpl(new AiRuntimeGatewayAuthority(runRegistrations), runDispatch,
                runOutcomes, new AiFeatureGate(true));
        managementService = new AiRuntimeManagementGatewayServiceImpl(
                new AiRuntimeManagementGatewayAuthority(managementRegistrations), managementDispatch,
                managementAssignments, managementOutcomes, new AiFeatureGate(true));
        Instant now = Instant.now();
        var authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(30), now.plusSeconds(900));
        var server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")), now.minusSeconds(10),
                now.plusSeconds(600));
        var roots = KeyStore.getInstance("PKCS12");
        roots.load(null, null);
        roots.setCertificateEntry("authority", authority.certificate());
        var trusted = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        trusted.init(roots);
        var keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("server", server.keys().getPrivate(), new char[0], chain(server, authority));
        var keyFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        keyFactory.init(keys, new char[0]);
        var keyManager = (X509ExtendedKeyManager) keyFactory.getKeyManagers()[0];
        var policy = new RuntimeProxyTrustManager.Policy(
                RuntimeProxyTrustManagerTest.authorities(authority.certificate()), Set.of(), now, now.plusSeconds(30));
        listeners = new ArrayList<>();
        for (RuntimePeerRole role : RuntimePeerRole.values()) {
            var client = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                    new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier, role.certificateUri(SUBJECT))),
                    now.minusSeconds(10), now.plusSeconds(600));
            CLIENTS.put(role, tlsContext(client, chain(client, authority), trusted.getTrustManagers()));
            listeners
                    .add(new RuntimeProxyTransport.Listener(role, InetAddress.getLoopbackAddress(), 0, keyManager,
                            new RuntimeProxyTrustManager(() -> policy, Clock.fixed(now, ZoneOffset.UTC), role)));
        }
        transport = RuntimeProxyTransport.forListeners("/api", listeners);
        tomcat = new Tomcat();
        tomcat.setBaseDir(directory.toString());
        tomcat.setPort(0);
        tomcat.getConnector().setProperty("address", "127.0.0.1");
        transport.connectors().values().forEach(tomcat.getService()::addConnector);
        tomcat.getEngine().getPipeline().addValve(transport.boundary());
        var context = tomcat.addContext("/api", directory.toString());
        transport.installDispatchGuard(context);
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
        CALLS.set(0);
        clearInvocations(runRegistrations, managementRegistrations, runDispatch, managementDispatch, runOutcomes,
                managementAssignments, managementOutcomes);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void physicalListenerCarriesItsOwnAuthenticatedRole(RuntimePeerRole role) throws Exception {
        try (var client = client(role)) {
            var response = send(client, role, ROUTES.get(role));
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo(role.name());
            assertThat(response.headers().firstValue("X-Runner-Projection"))
                    .contains(Boolean.toString(role == RuntimePeerRole.RUNNER_PROXY));
            assertThat(response.headers().firstValue("X-Async-Supported")).contains("false");
            assertThat(CALLS).hasValue(1);
        }
    }

    @ParameterizedTest
    @EnumSource(value = RuntimePeerRole.class, names = {"GATEWAY_RUN", "GATEWAY_MANAGEMENT"})
    void actualNativeRegistrationGetReachesOwnTypedPendingWithoutAnyBusinessEffect(RuntimePeerRole role)
            throws Exception {
        try (var http = client(role)) {
            var reply = sendMethod(http, role, REGISTRATIONS.get(role), "GET");
            verifyNoInteractions(runDispatch, managementDispatch, runOutcomes, managementAssignments,
                    managementOutcomes);
            assertThat(reply.statusCode()).isEqualTo(200);
            assertThat(reply.body())
                    .isEqualTo(
                            "{\"version\":1,\"kind\":\"" + (role == RuntimePeerRole.GATEWAY_RUN ? "run" : "management")
                                    + "-gateway-registration-pending\"}");
            assertThat(CALLS).hasValue(1);
            assertThat(reply.headers().firstValue("X-Async-Supported")).contains("false");
            if (role == RuntimePeerRole.GATEWAY_RUN) {
                verify(runRegistrations)
                        .current(argThat(peer -> peer.role() == role && peer.subject().equals(SUBJECT)), any());
                verifyNoInteractions(managementRegistrations);
            } else {
                verify(managementRegistrations)
                        .current(argThat(peer -> peer.role() == role && peer.subject().equals(SUBJECT)), any());
                verifyNoInteractions(runRegistrations);
            }
        }
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void nativeRegistrationMethodCatalogRejectsForeignRoutesQueriesAndPostOnGetOnlyPaths(RuntimePeerRole role)
            throws Exception {
        try (var http = client(role)) {
            assertThat(sendMethod(http, role, ROUTES.get(role), "GET").statusCode()).isEqualTo(403);
            for (var entry : REGISTRATIONS.entrySet()) {
                assertThat(sendMethod(http, role, entry.getValue(), "POST").statusCode()).isEqualTo(403);
                if (entry.getKey() != role) {
                    assertThat(sendMethod(http, role, entry.getValue(), "GET").statusCode()).isEqualTo(403);
                } else {
                    assertThat(sendMethod(http, role, entry.getValue() + "?role=CONTROLLER", "GET").statusCode())
                            .isEqualTo(403);
                    assertThat(sendMethod(http, role, entry.getValue().replace("registration", "%72egistration"), "GET")
                            .statusCode()).isEqualTo(403);
                }
            }
        }
        assertThat(CALLS).hasValue(0);
        verifyNoInteractions(runRegistrations, managementRegistrations, runDispatch, managementDispatch, runOutcomes,
                managementAssignments, managementOutcomes);
    }

    @Test
    void ordinaryIngressCannotSelectEitherRegistrationGetWithRoleHeaders() throws Exception {
        try (var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()) {
            for (String route : REGISTRATIONS.values()) {
                var request = HttpRequest
                        .newBuilder(URI.create("http://localhost:" + tomcat.getConnector().getLocalPort() + route))
                        .timeout(Duration.ofSeconds(3))
                        .header("X-Runtime-Role", "GATEWAY_MANAGEMENT")
                        .header("X-Forwarded-Proto", "https")
                        .GET()
                        .build();
                assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
            }
        }
        assertThat(CALLS).hasValue(0);
        verifyNoInteractions(runRegistrations, managementRegistrations, runDispatch, managementDispatch, runOutcomes,
                managementAssignments, managementOutcomes);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void sameCaCertificateCannotSelectAnotherPhysicalAudience(RuntimePeerRole caller) throws Exception {
        for (RuntimePeerRole target : RuntimePeerRole.values()) {
            if (caller == target) {
                continue;
            }
            try (var client = client(caller)) {
                assertThatThrownBy(() -> send(client, target, ROUTES.get(target))).isInstanceOf(SSLException.class);
            }
        }
        assertThat(CALLS).hasValue(0);
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void correctCertificateCannotReachAnotherRolesRoute(RuntimePeerRole caller) throws Exception {
        try (var client = client(caller)) {
            for (RuntimePeerRole target : RuntimePeerRole.values()) {
                if (caller != target) {
                    assertThat(send(client, caller, ROUTES.get(target)).statusCode()).isEqualTo(403);
                }
            }
            assertThat(send(client, caller, "/api/ordinary").statusCode()).isEqualTo(403);
        }
        assertThat(CALLS).hasValue(0);
    }

    @Test
    void ordinaryConnectorAndHeadersCannotSelectAnyNativeAudience() throws Exception {
        try (var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()) {
            for (String route : ROUTES.values()) {
                var request = HttpRequest
                        .newBuilder(URI.create("http://localhost:" + tomcat.getConnector().getLocalPort() + route))
                        .timeout(Duration.ofSeconds(3))
                        .header("X-Runtime-Role", "GATEWAY_MANAGEMENT")
                        .header("X-Forwarded-Proto", "https")
                        .header("Authorization", "Bearer ignored")
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build();
                assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
            }
            var ordinary = HttpRequest
                    .newBuilder(
                            URI.create("http://localhost:" + tomcat.getConnector().getLocalPort() + "/api/ordinary"))
                    .GET()
                    .build();
            assertThat(client.send(ordinary, HttpResponse.BodyHandlers.ofString()).body()).isEqualTo("ordinary");
        }
        assertThat(CALLS).hasValue(0);
    }

    @Test
    void ambiguousListenerConfigurationFailsBeforeInstallation() {
        assertThatThrownBy(transport::connector).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> transport.connectors().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> RuntimeProxyTransport.forListeners("/api", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                () -> RuntimeProxyTransport.forListeners("/api", List.of(listeners.get(0), listeners.get(0))))
                .isInstanceOf(IllegalArgumentException.class);
        var runner = listeners.get(0);
        assertThatThrownBy(() -> new RuntimeProxyTransport.Listener(RuntimePeerRole.GATEWAY_RUN, runner.address(),
                runner.port(), runner.keys(), runner.trust())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void dispatchGuardRejectsAMissingOrHostOnlyBoundary() throws Exception {
        var candidate = RuntimeProxyTransport.forListeners("/api", listeners);
        var wrong = new Tomcat();
        wrong.setBaseDir(directory.resolve("missing-engine").toString());
        var context = wrong.addContext("/api", directory.toString());
        try {
            assertThatThrownBy(() -> candidate.installDispatchGuard(context))
                    .isInstanceOf(IllegalArgumentException.class);
            wrong.getHost().getPipeline().addValve(candidate.boundary());
            assertThatThrownBy(() -> candidate.installDispatchGuard(context))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThat(context.findFilterDefs()).isEmpty();
        } finally {
            wrong.destroy();
        }
    }

    @Test
    void nativeListenersCannotBindWithoutTheOwningEngineBoundary() throws Exception {
        var candidate = RuntimeProxyTransport.forListeners("/api", listeners);
        var wrong = new Tomcat();
        wrong.setBaseDir(directory.resolve("unbound-native").toString());
        wrong.setPort(0);
        wrong.getConnector().setProperty("address", "127.0.0.1");
        candidate.connectors().values().forEach(wrong.getService()::addConnector);
        var context = wrong.addContext("/api", directory.toString());
        Tomcat.addServlet(context, "ordinary", new ProbeServlet());
        context.addServletMappingDecoded("/*", "ordinary");
        try {
            wrong.start();
            assertThat(candidate.connectors().values()).allSatisfy(connector -> {
                assertThat(connector.getState().isAvailable()).isFalse();
                assertThat(connector.getLocalPort()).isNegative();
            });
            try (var client = HttpClient.newHttpClient()) {
                var uri = URI.create("http://localhost:" + wrong.getConnector().getLocalPort() + "/api/ordinary");
                assertThat(client
                        .send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString())
                        .body()).isEqualTo("ordinary");
            }
        } finally {
            try {
                wrong.stop();
            } finally {
                wrong.destroy();
            }
        }
    }

    @Test
    void duplicateFixedAddressAndPortIsRejectedBeforeConnectorCreation() {
        var a = listeners.get(0);
        var b = listeners.get(1);
        var first = new RuntimeProxyTransport.Listener(a.role(), a.address(), 9443, a.keys(), a.trust());
        var second = new RuntimeProxyTransport.Listener(b.role(), a.address(), 9443, b.keys(), b.trust());
        assertThatThrownBy(() -> RuntimeProxyTransport.forListeners("/api", List.of(first, second)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unattachedEngineAndConnectorCannotMatchThroughNullServices() throws Exception {
        var candidate = RuntimeProxyTransport.forListeners("/api", listeners);
        var engine = new org.apache.catalina.core.StandardEngine();
        engine.getPipeline().addValve(candidate.boundary());
        try {
            var boundary = (RuntimeProxyBoundaryValve) candidate.boundary();
            assertThat(candidate.connectors().values())
                    .allSatisfy(connector -> assertThat(boundary.installedFor(connector)).isFalse());
        } finally {
            engine.destroy();
        }
    }

    @Test
    void liveServiceCannotStartNewNativeListenersWithoutTheBoundary() throws Exception {
        var candidate = RuntimeProxyTransport.forListeners("/api", listeners);
        var wrong = new Tomcat();
        wrong.setBaseDir(directory.resolve("live-missing-engine").toString());
        wrong.setPort(0);
        wrong.getConnector().setProperty("address", "127.0.0.1");
        var context = wrong.addContext("/api", directory.toString());
        Tomcat.addServlet(context, "ordinary", new ProbeServlet());
        context.addServletMappingDecoded("/*", "ordinary");
        try {
            wrong.start();
            for (var connector : candidate.connectors().values()) {
                wrong.getService().addConnector(connector);
                assertThat(connector.getState().isAvailable()).isFalse();
                assertThat(connector.getLocalPort()).isNegative();
            }
            try (var client = HttpClient.newHttpClient()) {
                var uri = URI.create("http://localhost:" + wrong.getConnector().getLocalPort() + "/api/ordinary");
                assertThat(client
                        .send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString())
                        .body()).isEqualTo("ordinary");
            }
        } finally {
            try {
                wrong.stop();
            } finally {
                wrong.destroy();
            }
        }
    }

    private static HttpClient client(RuntimePeerRole role) {
        return HttpClient
                .newBuilder()
                .sslContext(CLIENTS.get(role))
                .connectTimeout(Duration.ofSeconds(2))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    private static HttpResponse<String> send(HttpClient client, RuntimePeerRole listener, String path)
            throws Exception {
        int port = transport.connectors().get(listener).getLocalPort();
        var request = HttpRequest
                .newBuilder(URI.create("https://localhost:" + port + path))
                .timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json")
                .header("X-Runtime-Role", "ignored")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> sendMethod(HttpClient http, RuntimePeerRole listener, String path,
            String method) throws Exception {
        int port = transport.connectors().get(listener).getLocalPort();
        var request = HttpRequest
                .newBuilder(URI.create("https://localhost:" + port + path))
                .timeout(Duration.ofSeconds(3))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static final class ProbeServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
            if (request.getRequestURI().equals("/api/ordinary")) {
                response.getWriter().write("ordinary");
                return;
            }
            var peer = RuntimeProxyTransport.currentWorkloadPeer().orElseThrow();
            CALLS.incrementAndGet();
            response
                    .setHeader("X-Runner-Projection",
                            Boolean.toString(RuntimeProxyTransport.currentPeer().isPresent()));
            response.setHeader("X-Async-Supported", Boolean.toString(request.isAsyncSupported()));
            if (request.getRequestURI().equals(REGISTRATIONS.get(RuntimePeerRole.GATEWAY_RUN))
                    || request.getRequestURI().equals(REGISTRATIONS.get(RuntimePeerRole.GATEWAY_MANAGEMENT))) {
                var reply = peer.role() == RuntimePeerRole.GATEWAY_RUN
                        ? runService.registration()
                        : managementService.registration();
                response.setStatus(reply.getStatusCode().value());
                response.setContentType("application/json");
                response.getOutputStream().write(java.util.Objects.requireNonNull(reply.getBody()));
                return;
            }
            response.getWriter().write(peer.role().name());
        }
    }
}
