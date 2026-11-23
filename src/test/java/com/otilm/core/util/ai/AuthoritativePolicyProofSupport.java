package com.otilm.core.util.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.otilm.core.messaging.jms.producers.AuditLogsProducer;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.opa.AuthorizationCache;
import com.otilm.core.util.MockModuleTestSupport;
import com.otilm.core.util.lifecycle.TestSessionContextOwner;
import com.otilm.core.util.mockbeans.PollMocks;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * One context, genuine pinned OPA policies, disposable PostgreSQL, and an observed HTTP transport. Requires a local
 * Docker engine over a Unix socket; all task-owned fixture ports bind to loopback.
 */
@SpringBootTest
@Import({AuthoritativePolicyProofConfiguration.class, ProducerMocks.class, PollMocks.class})
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
public abstract class AuthoritativePolicyProofSupport extends MockModuleTestSupport {
    protected static final ObjectMapper JSON = new ObjectMapper();
    private static final PostgreSQLContainer<?> DATABASE = new PostgreSQLContainer<>(DockerImageName
            .parse("postgres@sha256:09e4f20b14ddb3dfe3a0c825b206032aaf8f28300ba2070c0b60fc1c10c6abc7")
            .asCompatibleSubstituteFor("postgres"))
            .withInitScript("ai/authorization/schema.sql")
            .withCreateContainerCmdModifier(command -> command
                    .getHostConfig()
                    .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(5432))))
            .withLabel("com.otilm.ai-proof.task", "f05-f06-task1");
    protected static final Authority AUTHORITY = new Authority();
    private static final ProofDatabaseLifecycle FIXTURES = new ProofDatabaseLifecycle(DATABASE, AUTHORITY::close);

    static {
        if (TestSessionContextOwner.isEnabled()) {
            SpringApplication.getShutdownHandlers().add(() -> {
                String output = System.getProperty(ProofDatabaseLifecycle.STOP_RECORD_PROPERTY);
                FIXTURES.stopAfterContexts(output == null ? null : Path.of(output));
            });
        } else {
            Runtime.getRuntime().addShutdownHook(new Thread(AuthoritativePolicyProofSupport::stopFixtures));
        }
    }

    private static void stopFixtures() {
        FIXTURES.stop();
    }

    @MockitoBean
    protected AuditLogsProducer auditLogsProducer;
    @Autowired
    protected PlatformAuthenticationClient authenticationClient;
    @Autowired
    protected AuthorizationCache authorizationCache;

    @DynamicPropertySource
    static void authorities(DynamicPropertyRegistry properties) {
        FIXTURES.start();
        properties.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        properties.add("spring.datasource.url", () -> BaseAiSpringBootTest.jdbcUrl(DATABASE));
        properties.add("spring.datasource.username", DATABASE::getUsername);
        properties.add("spring.datasource.password", DATABASE::getPassword);
        properties.add("auth-service.base-url", AUTHORITY::url);
        properties.add("opa.base-url", AUTHORITY::url);
    }

    protected void authenticate(UUID actor, String principal) {
        AUTHORITY.principal = principal;
        AUTHORITY.anonymous = false;
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(
                        new PlatformUserDetails(authenticationClient.authenticateByUserUuid(actor))));
    }

    protected Map<String, List<Ports.Binding>> fixturePortBindings() {
        return Map
                .of("opa", ProofDatabaseLifecycle.actualPortBindings(AUTHORITY.opa), "postgres",
                        ProofDatabaseLifecycle.actualPortBindings(DATABASE));
    }

    @AfterEach
    void clearThreadIdentity() {
        SecurityContextHolder.clearContext();
        org.slf4j.MDC.clear();
    }

    /** Synthetic Auth is a wiring fixture, not verification of the actual Auth service's revocation code. */
    public static final class Authority implements AutoCloseable {
        private final GenericContainer<?> opa = new GenericContainer<>(DockerImageName
                .parse("openpolicyagent/opa@sha256:60b6af32b58377718546ac7d4634eecbfe50ec36f7d3ca3f8ebf515f9826c2ac"))
                .withLabel("com.otilm.ai-proof.task", "f05-f06-task1")
                .withExposedPorts(8181)
                .withCreateContainerCmdModifier(command -> command
                        .getHostConfig()
                        .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(8181))))
                .withCopyFileToContainer(MountableFile.forClasspathResource("ai/authorization/method_policy.rego"),
                        "/policies/method_policy.rego")
                .withCopyFileToContainer(MountableFile.forClasspathResource("ai/authorization/objects_policy.rego"),
                        "/policies/objects_policy.rego")
                .withCommand("run", "--server", "--addr=0.0.0.0:8181", "/policies")
                .waitingFor(Wait.forHttp("/health"));
        private final HttpServer server;
        private final HttpClient transport = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        public final List<Exchange> exchanges = new CopyOnWriteArrayList<>();
        public volatile String principal;
        public volatile boolean anonymous;
        public volatile boolean opaUnavailable;
        public volatile String opaErrorMessage;
        public volatile int authStatus = 200;
        public volatile java.util.function.BiConsumer<String, JsonNode> beforeRequest;
        public volatile String authResponseOverride;
        public volatile String malformedOpaResponse;
        public volatile java.util.concurrent.CountDownLatch authResponseRelease;
        public volatile java.util.concurrent.CountDownLatch opaResponseRelease;

        Authority() {
            HttpServer pendingServer = null;
            try {
                String host = DockerClientFactory.instance().dockerHostIpAddress();
                if (!"unix".equals(DockerClientFactory.instance().getTransportConfig().getDockerHost().getScheme())
                        || !("localhost".equals(host) || "127.0.0.1".equals(host))) {
                    throw new IllegalStateException("Authorization proof fixtures require a local Docker engine "
                            + "over a Unix socket with loopback access; remote Docker engines are unsupported.");
                }
                verifyPolicyPin();
                opa.start();
                ProofDatabaseLifecycle.requireLoopbackBinding(opa);
                pendingServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                pendingServer.createContext("/", this::handle);
                pendingServer.start();
                server = pendingServer;
            } catch (IOException | RuntimeException failure) {
                try {
                    if (pendingServer != null) {
                        pendingServer.stop(0);
                    }
                } finally {
                    opa.stop();
                }
                throw new IllegalStateException("Unable to start authorization proof authorities.", failure);
            }
        }

        private void handle(HttpExchange request) throws IOException {
            String path = request.getRequestURI().getPath();
            JsonNode requestBody = JSON.createObjectNode();
            JsonNode response;
            int status;
            try {
                String body = new String(request.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                requestBody = JSON.readTree(body);
                if (beforeRequest != null) {
                    beforeRequest.accept(path, requestBody);
                }
                if (path.equals("/auth")) {
                    awaitResponseRelease(authResponseRelease);
                    status = authStatus;
                    response = authResponseOverride != null
                            ? JSON.readTree(authResponseOverride)
                            : JSON
                                    .valueToTree(anonymous
                                            ? Map.of("authenticated", false)
                                            : Map.of("authenticated", true, "data", JSON.readTree(principal)));
                } else if (malformedOpaResponse != null) {
                    status = 200;
                    response = JSON.readTree(malformedOpaResponse);
                } else if (opaUnavailable) {
                    status = 503;
                    response = JSON
                            .createObjectNode()
                            .put("message", opaErrorMessage == null ? "synthetic OPA unavailable" : opaErrorMessage);
                } else {
                    awaitResponseRelease(opaResponseRelease);
                    HttpResponse<String> upstream = transport
                            .send(HttpRequest
                                    .newBuilder(URI
                                            .create("http://" + opa.getHost() + ":" + opa.getMappedPort(8181) + path))
                                    .header("Content-Type", "application/json")
                                    .POST(HttpRequest.BodyPublishers.ofString(body))
                                    .build(), HttpResponse.BodyHandlers.ofString());
                    status = upstream.statusCode();
                    response = JSON.readTree(upstream.body());
                }
            } catch (IOException | RuntimeException | InterruptedException failure) {
                if (failure instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                status = 500;
                response = JSON.createObjectNode().put("message", "Synthetic authority fixture failure");
            }
            exchanges.add(new Exchange(path, requestBody, status, response));
            try {
                byte[] bytes = JSON.writeValueAsBytes(response);
                request.getResponseHeaders().set("Content-Type", "application/json");
                request.sendResponseHeaders(status, bytes.length);
                request.getResponseBody().write(bytes);
            } finally {
                request.close();
            }
        }

        @Override
        public void close() {
            try {
                server.stop(0);
            } finally {
                opa.stop();
            }
        }

        private void verifyPolicyPin() throws IOException {
            try (var manifestStream = AuthoritativePolicyProofSupport.class
                    .getResourceAsStream("/ai/authorization/fixture-manifest.json")) {
                JsonNode manifest = JSON.readTree(java.util.Objects.requireNonNull(manifestStream));
                for (String policy : List.of("method", "objects")) {
                    try (var bytes = AuthoritativePolicyProofSupport.class
                            .getResourceAsStream("/ai/authorization/" + policy + "_policy.rego")) {
                        String actual = java.util.HexFormat
                                .of()
                                .formatHex(java.security.MessageDigest
                                        .getInstance("SHA-256")
                                        .digest(java.util.Objects.requireNonNull(bytes).readAllBytes()));
                        if (!actual.equals(manifest.path("policies").path(policy + "FixtureSha256").asText())) {
                            throw new IOException("Pinned " + policy + " policy hash mismatch");
                        }
                    }
                }
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        private static void awaitResponseRelease(java.util.concurrent.CountDownLatch release)
                throws InterruptedException {
            if (release != null && !release.await(5, java.util.concurrent.TimeUnit.SECONDS)) {
                throw new IllegalStateException("Authority fixture response was not released");
            }
        }

        public void installTestMethodDeny() throws Exception {
            String module = "package method\nimport rego.v1\ndeny contains \"SyntheticFaultInjection\" if { true }\n";
            policyCall("PUT", "/v1/policies/synthetic-method-deny", module);
        }

        public void removeTestMethodDeny() throws Exception {
            policyCall("DELETE", "/v1/policies/synthetic-method-deny", "");
        }

        public PolicySource objectPolicySource() throws Exception {
            JsonNode response = JSON.readTree(policyCall("GET", "/v1/policies", ""));
            for (JsonNode policy : response.path("result")) {
                if (policy.path("raw").isTextual() && policy.path("raw").textValue().startsWith("package objects\n")) {
                    return new PolicySource(policy.path("id").asText(), policy.path("raw").textValue());
                }
            }
            throw new IllegalStateException("Disposable object policy source is unavailable");
        }

        public void installTestObjectDeny(PolicySource original, UUID certificate) throws Exception {
            String module = "package objects\nimport rego.v1\n"
                    + "actionAllowedForGroupOfObjects := false\nallowedObjects := []\n" + "forbiddenObjects := [\""
                    + certificate + "\"]\n";
            policyCall("PUT", policyPath(original), module);
        }

        public void restorePolicy(PolicySource original) throws Exception {
            policyCall("PUT", policyPath(original), original.raw());
        }

        private static String policyPath(PolicySource policy) {
            return "/v1/policies/" + java.net.URLEncoder.encode(policy.id(), StandardCharsets.UTF_8);
        }

        public record PolicySource(String id, String raw) {
        }

        public Map<String, String> runningPolicyHashes() throws Exception {
            JsonNode response = JSON.readTree(policyCall("GET", "/v1/policies", ""));
            Map<String, String> hashes = new java.util.TreeMap<>();
            for (JsonNode policy : response.path("result")) {
                if (!policy.path("raw").isTextual()) {
                    throw new IllegalStateException("Policy inspection did not return its source");
                }
                hashes
                        .put(policy.path("id").asText(), java.util.HexFormat
                                .of()
                                .formatHex(java.security.MessageDigest
                                        .getInstance("SHA-256")
                                        .digest(policy.path("raw").textValue().getBytes(StandardCharsets.UTF_8))));
            }
            return hashes;
        }

        private String policyCall(String method, String path, String body) throws Exception {
            var request = HttpRequest
                    .newBuilder(URI.create("http://" + opa.getHost() + ":" + opa.getMappedPort(8181) + path))
                    .timeout(Duration.ofSeconds(3))
                    .method(method, HttpRequest.BodyPublishers.ofString(body))
                    .build();
            var response = transport.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Disposable policy update or inspection failed");
            }
            return response.body();
        }

        public String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        public long count(String path) {
            return exchanges.stream().filter(exchange -> exchange.path().equals(path)).count();
        }

        public void reset() {
            principal = null;
            exchanges.clear();
            anonymous = false;
            opaUnavailable = false;
            opaErrorMessage = null;
            authStatus = 200;
            beforeRequest = null;
            authResponseOverride = null;
            malformedOpaResponse = null;
            authResponseRelease = null;
            opaResponseRelease = null;
        }
    }

    public record Exchange(String path, JsonNode request, int status, JsonNode response) {
    }
}
