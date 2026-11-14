package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.controller.KubernetesSnapshotVerifier;
import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/** Local authenticated API observations are component evidence, not native deployment attestation. */
class AiRuntimeControllerAuthorityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String NS = "a828cc5c-e462-4fa2-83d0-47be8905c507";
    private static final String SA = "4960a204-dca3-4097-8659-2d7b3bab0036";
    private static final String JOB = "606c8cf2-9b6c-436d-91c9-4e5931885ae5";
    private static final String POD = "42864334-b047-4067-8619-4d8d095b974c";
    private static final String RUNTIME = "c70c6236-e291-4918-8534-8406c7bc7f8f";
    private static final String IMAGE = "containerd://sha256:" + "a".repeat(64);
    private static final String GATE = "ilm.otilm.ai/runtime-eligible";
    private static final String SPEC = """
            {"serviceAccountName":"controller","runtimeClassName":"ilm-runsc","restartPolicy":"Never",
             "automountServiceAccountToken":false,"schedulingGates":[{"name":"%s"}],
             "containers":[{"name":"controller","image":"local.invalid/controller@sha256:%s",
               "command":["/opt/java/openjdk/bin/java","com.otilm.ai.controller.ControllerMain"],
               "securityContext":{"runAsUser":65533,"runAsGroup":65533,"allowPrivilegeEscalation":false}}]}
            """.formatted(GATE, "b".repeat(64));
    private static final String JOB_SPEC = "{\"template\":{\"spec\":" + SPEC + "}}";
    @TempDir
    Path directory;

    @Test
    void matchingNativeControllerMustAlsoPassCurrentAuthenticatedFullDeploymentObservation() throws Exception {
        try (var api = new Api(directory)) {
            var authority = new AiRuntimeControllerAuthority(api.source());
            var evidence = assertDoesNotThrow(
                    () -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()));
            assertThat(evidence.workload().podUid()).isEqualTo(POD);
            assertThat(evidence.workload().jobUid()).isEqualTo(JOB);
            assertThat(evidence.workload().stage()).isEqualTo(KubernetesSnapshotVerifier.Stage.RUNNING);
            assertThat(api.requests).hasValue(11);
            assertThat(api.invalidRequests).hasValue(0);
            assertThat(api.rawError).isNull();
        }
    }

    @Test
    void roleOrCertificateTupleMismatchIsDeniedBeforeAnyApiRequest() throws Exception {
        try (var api = new Api(directory)) {
            var authority = new AiRuntimeControllerAuthority(api.source());
            for (var role : new RuntimePeerRole[]{
                    RuntimePeerRole.RUNNER_PROXY,
                    RuntimePeerRole.GATEWAY_RUN,
                    RuntimePeerRole.GATEWAY_MANAGEMENT}) {
                assertThatThrownBy(() -> authority.requireCurrent(peer(role), AiRuntimeOperationBudget.start()))
                        .isInstanceOf(AccessDeniedException.class);
            }
            for (var subject : new RuntimeProxyCertificateClaims[]{
                    new RuntimeProxyCertificateClaims("other", "runtime", "controller", "controller-one",
                            UUID.fromString(POD)),
                    new RuntimeProxyCertificateClaims("lab", "other", "controller", "controller-one",
                            UUID.fromString(POD)),
                    new RuntimeProxyCertificateClaims("lab", "runtime", "other", "controller-one",
                            UUID.fromString(POD)),
                    new RuntimeProxyCertificateClaims("lab", "runtime", "controller", "other", UUID.fromString(POD)),
                    new RuntimeProxyCertificateClaims("lab", "runtime", "controller", "controller-one",
                            UUID.randomUUID())}) {
                assertThatThrownBy(() -> authority
                        .requireCurrent(new RuntimePeer(RuntimePeerRole.CONTROLLER, subject),
                                AiRuntimeOperationBudget.start()))
                        .isInstanceOf(AccessDeniedException.class);
            }
            assertThatThrownBy(() -> authority.requireCurrent(null, AiRuntimeOperationBudget.start()))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(api.requests).hasValue(0);
        }
    }

    @Test
    void copiedCertificateCannotAuthorizeAReplacedOrChangedCurrentPod() throws Exception {
        try (var api = new Api(directory)) {
            var authority = new AiRuntimeControllerAuthority(api.source());
            for (String field : new String[]{"uid", "resourceVersion"}) {
                var changed = api.pod.deepCopy();
                ((ObjectNode) changed.get("metadata"))
                        .put(field, field.equals("uid") ? UUID.randomUUID().toString() : "new-rv");
                api.laterPod = changed;
                assertThatThrownBy(() -> authority
                        .requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()))
                        .isInstanceOf(AccessDeniedException.class)
                        .hasMessage("Current controller deployment required")
                        .hasCause(null);
            }
            api.laterPod = null;
            ((ObjectNode) api.pod.path("spec").path("containers").get(0).path("securityContext"))
                    .put("allowPrivilegeEscalation", true);
            assertThatThrownBy(
                    () -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()))
                    .isInstanceOf(AccessDeniedException.class);
        }
    }

    @Test
    void expiredBudgetAndApiFailureCannotReturnCachedAuthority() throws Exception {
        try (var api = new Api(directory)) {
            var authority = new AiRuntimeControllerAuthority(api.source());
            assertDoesNotThrow(
                    () -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()));
            api.status = 503;
            assertThatThrownBy(
                    () -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()))
                    .isInstanceOf(AccessDeniedException.class);
            int before = api.requests.get();
            var expired = AiRuntimeOperationBudget.start(Duration.ofNanos(1));
            assertThatThrownBy(() -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), expired))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(api.requests).hasValue(before);
        }
    }

    @Test
    void missingBudgetIsDeniedBeforeApiIo() throws Exception {
        try (var api = new Api(directory)) {
            var authority = new AiRuntimeControllerAuthority(api.source());
            assertThatThrownBy(() -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), null))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(api.requests).hasValue(0);
        }
    }

    @Test
    void anActiveObservationHasNoApplicationQueueOrCompetingApiOwner() throws Exception {
        try (var api = new Api(directory)) {
            api.block = true;
            var authority = new AiRuntimeControllerAuthority(api.source());
            var pending = new java.util.concurrent.FutureTask<>(
                    () -> authority.requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()));
            var first = Thread.ofPlatform().daemon().name("controller-authority-fixture").start(pending);
            try {
                assertThat(api.entered.await(2, TimeUnit.SECONDS)).isTrue();
                assertThatThrownBy(() -> authority
                        .requireCurrent(peer(RuntimePeerRole.CONTROLLER), AiRuntimeOperationBudget.start()))
                        .isInstanceOf(AccessDeniedException.class);
                assertThat(api.requests).hasValue(1);
                api.block = false;
                api.release.countDown();
                assertThat(pending.get(3, TimeUnit.SECONDS).workload().podUid()).isEqualTo(POD);
                assertThat(api.requests).hasValue(11);
            } finally {
                api.block = false;
                api.release.countDown();
                first.join(5000);
                assertThat(first.isAlive()).isFalse();
            }
        }
    }

    private static RuntimePeer peer(RuntimePeerRole role) {
        return new RuntimePeer(role, new RuntimeProxyCertificateClaims("lab", "runtime", "controller", "controller-one",
                UUID.fromString(POD)));
    }

    private static final class Api implements AutoCloseable {
        private final HttpsServer server;
        private final java.util.concurrent.ExecutorService executor = Executors.newCachedThreadPool();
        private final Map<String, ObjectNode> routes = new LinkedHashMap<>();
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger invalidRequests = new AtomicInteger();
        private final Path ca;
        private final Path token;
        private final ObjectNode pod;
        private volatile ObjectNode laterPod;
        private volatile int status = 200;
        private volatile Throwable rawError;
        private volatile boolean block;
        private final java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
        private final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);

        private Api(Path directory) throws Exception {
            Instant now = Instant.now();
            var authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(60),
                    now.plusSeconds(600));
            var certificate = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "kube.invalid")), now.minusSeconds(30),
                    now.plusSeconds(300));
            var store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("server", certificate.keys().getPrivate(), new char[0], chain(certificate, authority));
            var managers = KeyManagerFactory.getInstance("SunX509");
            managers.init(store, new char[0]);
            var tls = SSLContext.getInstance("TLS");
            tls.init(managers.getKeyManagers(), null, null);
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(tls));
            server.setExecutor(executor);
            String scope = "/api/v1/namespaces/runtime";
            routes.put(scope, object("v1", "Namespace", "runtime", NS, null));
            routes
                    .put(scope + "/serviceaccounts/controller",
                            object("v1", "ServiceAccount", "controller", SA, "runtime"));
            var job = object("batch/v1", "Job", "controller-job", JOB, "runtime");
            job.set("spec", JSON.readTree(JOB_SPEC));
            routes.put("/apis/batch/v1/namespaces/runtime/jobs/controller-job", job);
            var runtime = object("node.k8s.io/v1", "RuntimeClass", "ilm-runsc", RUNTIME, null);
            runtime.put("handler", "runsc");
            routes.put("/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc", runtime);
            pod = object("v1", "Pod", "controller-one", POD, "runtime");
            ((ObjectNode) pod.path("metadata"))
                    .putArray("ownerReferences")
                    .addObject()
                    .put("apiVersion", "batch/v1")
                    .put("kind", "Job")
                    .put("name", "controller-job")
                    .put("uid", JOB)
                    .put("controller", true);
            var actualSpec = (ObjectNode) JSON.readTree(SPEC);
            actualSpec.remove("schedulingGates");
            actualSpec.put("nodeName", "node-one");
            pod.set("spec", actualSpec);
            var statusNode = pod.putObject("status").put("phase", "Running");
            statusNode
                    .putArray("containerStatuses")
                    .addObject()
                    .put("name", "controller")
                    .put("restartCount", 0)
                    .put("imageID", IMAGE)
                    .put("started", true)
                    .put("ready", true)
                    .putObject("state")
                    .putObject("running");
            routes.put(scope + "/pods/controller-one", pod);
            ca = Files.createTempFile(directory, "ca-", ".der");
            Files.write(ca, authority.certificate().getEncoded());
            token = Files.createTempFile(directory, "token-", ".txt");
            Files.writeString(token, "synthetic.controller.token");
            Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
            server.createContext("/", exchange -> {
                try (exchange) {
                    int count = requests.incrementAndGet();
                    if (block) {
                        entered.countDown();
                        if (!release.await(4, TimeUnit.SECONDS)) {
                            throw new AssertionError("Synthetic API owner was not released");
                        }
                    }
                    if (!"GET".equals(exchange.getRequestMethod()) || !"Bearer synthetic.controller.token"
                            .equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                        invalidRequests.incrementAndGet();
                    }
                    String path = exchange.getRequestURI().toString();
                    ObjectNode response = routes.get(path);
                    if ((scope + "/pods").equals(path)) {
                        response = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
                        response.putObject("metadata").put("resourceVersion", "list-rv");
                        response.putArray("items").add(count % 11 == 0 && laterPod != null ? laterPod : pod);
                    }
                    byte[] body = JSON.writeValueAsBytes(response);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(response == null ? 404 : this.status, body.length);
                    exchange.getResponseBody().write(body);
                } catch (Throwable failure) {
                    rawError = failure;
                }
            });
            server.start();
        }

        private AiRuntimeControllerAuthority.Source source() {
            var endpoint = new CoreEndpoint(URI.create("https://kube.invalid:" + server.getAddress().getPort()),
                    InetAddress.getLoopbackAddress());
            var pins = new KubernetesSnapshotVerifier.Pins("runtime", NS, "controller", SA, "controller-job", JOB,
                    "controller-one", POD, "ilm-runsc", RUNTIME, "runsc", GATE, SPEC, JOB_SPEC,
                    "{\"handler\":\"runsc\"}", "{\"labels\":{},\"annotations\":{}}", Map.of("controller", IMAGE));
            return new AiRuntimeControllerAuthority.Source("lab", new KubernetesConfiguration(endpoint, ca, token),
                    pins);
        }

        private static ObjectNode object(String api, String kind, String name, String uid, String namespace) {
            var value = JSON.createObjectNode().put("apiVersion", api).put("kind", kind);
            var metadata = value.putObject("metadata").put("name", name).put("uid", uid).put("resourceVersion", "rv-1");
            if (namespace != null) {
                metadata.put("namespace", namespace);
            }
            return value;
        }

        @Override
        public void close() throws Exception {
            release.countDown();
            server.stop(0);
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }
}
