package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.proxy.IdentityFiles;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.ai.AiRuntimeControllerServiceImpl;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.mock.env.MockEnvironment;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** Synthetic local authenticated API/bootstrap composition only; no real Kubernetes/native authority acceptance. */
@ExtendWith(MockitoExtension.class)
class AiRuntimeNativeMaterialProducerTest {
    private static final String TIMER_NAME = "ilm-ai-native-material";
    @TempDir
    Path directory;
    @Mock
    AiRuntimeNativeStartupWriter startup;

    @Test
    void publishesFourRoleMaterial_whenAuthenticatedPolicyAndServerKeysAreValid() throws Exception {
        // given
        Set<Thread> before = materialThreads();
        var returnedDenial = new AtomicBoolean();
        doAnswer(call -> {
            returnedDenial.set(true);
            return null;
        }).when(startup).disableAndConfirm(any());
        var ownedThread = new AtomicReference<Thread>();
        try (var api = new Api(directory, false, returnedDenial)) {
            Path bootstrap = api.bootstrap();

            // when
            context(bootstrap).run(application -> {
                // then
                assertThat(application).hasNotFailed();
                assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                RuntimeProxyTransport transport = application.getBean(RuntimeProxyTransport.class);
                assertThat(transport.disabled()).isFalse();
                assertThat(transport.connectors()).containsOnlyKeys(RuntimePeerRole.values());
                assertThat(application.getBean(AiRuntimeControllerAuthority.class)).isNotNull();
                AiRuntimeControllerServiceImpl.Source source = application
                        .getBean(AiRuntimeControllerServiceImpl.Source.class);
                assertThat(source.api().endpoint().origin().toString()).isEqualTo(api.origin());
                assertThat(source.api().endpoint().address().getHostAddress()).isEqualTo("127.0.0.1");
                assertThat(source.workloadProfiles()).isEqualTo(api.profiles);
                assertThat(api.paths)
                        .startsWith(Api.NAMESPACE_PATH, Api.POLICY_PATH, Api.NAMESPACE_PATH, Api.NAMESPACE_PATH,
                                Api.POLICY_PATH, Api.NAMESPACE_PATH);
                assertThat(api.requests.get()).isGreaterThanOrEqualTo(6);
                assertThat(api.invalidRequests).hasValue(0);
                assertThat(api.beforeDenial).hasValue(0);
                verify(startup).disableAndConfirm(any(AiRuntimeOperationBudget.class));
                ownedThread.set(ownedMaterialThread(before));
                assertThat(ownedThread.get().isAlive()).isTrue();
            });

            // The exact timer observed alive above must terminate through context close, before API/test teardown.
            assertThat(ownedThread.get()).isNotNull();
            await()
                    .pollInSameThread()
                    .atMost(Duration.ofSeconds(2))
                    .untilAsserted(() -> assertThat(ownedThread.get().isAlive()).isFalse());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"api500", "client-purpose"})
    void preservesOrdinaryContextWithoutTransport_whenInitialMaterialIsUnavailable(String failure) throws Exception {
        // given
        var returnedDenial = new AtomicBoolean();
        doAnswer(call -> {
            returnedDenial.set(true);
            return null;
        }).when(startup).disableAndConfirm(any());
        try (var api = new Api(directory, failure.equals("client-purpose"), returnedDenial)) {
            api.status = failure.equals("api500") ? 500 : 200;
            Path bootstrap = api.bootstrap();
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                    .getLogger(AiRuntimeNativeMaterialConfiguration.class);
            var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
            events.start();
            logger.addAppender(events);

            // when
            try {
                context(bootstrap).run(application -> {
                    // then
                    assertThat(application).hasNotFailed();
                    assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                    assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
                    assertThat(application.getBeanProvider(AiRuntimeControllerAuthority.class).getIfUnique()).isNull();
                    assertThat(application.getBeanProvider(AiRuntimeControllerServiceImpl.Source.class).getIfUnique())
                            .isNull();
                    assertThat(api.invalidRequests).hasValue(0);
                    assertThat(api.beforeDenial).hasValue(0);
                    assertThat(api.requests).hasValue(failure.equals("api500") ? 1 : 0);
                    verify(startup).disableAndConfirm(any(AiRuntimeOperationBudget.class));
                });
                assertThat(events.list)
                        .extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage)
                        .contains("AI runtime native material operation=startup status=UNAVAILABLE")
                        .doesNotContain("AI runtime native material operation=startup status=UNCONFIRMED");
            } finally {
                logger.detachAppender(events);
                events.stop();
            }
        }
    }

    @Test
    void permanentlyPoisonsBeforeDatabaseFailure_whenARefreshCannotVerifyPolicy() throws Exception {
        // given
        var returnedDenial = new AtomicBoolean();
        var calls = new AtomicInteger();
        var transport = new AtomicReference<RuntimeProxyTransport>();
        var disabledBeforeDatabase = new AtomicBoolean();
        doAnswer(call -> {
            if (calls.incrementAndGet() == 1) {
                returnedDenial.set(true);
                return null;
            }
            disabledBeforeDatabase.set(transport.get().disabled());
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }).when(startup).disableAndConfirm(any());
        try (var api = new Api(directory, false, returnedDenial)) {
            Path bootstrap = api.bootstrap();
            var configuration = new AiRuntimeNativeMaterialConfiguration();
            var environment = new MockEnvironment()
                    .withProperty("otilm.ai.runtime.native-material-file", bootstrap.toString())
                    .withProperty("server.servlet.context-path", "/api");
            var writers = new StaticListableBeanFactory(Map.of("startup", startup));
            try (var material = configuration
                    .aiRuntimeNativeMaterials(environment,
                            writers.getBeanProvider(AiRuntimeNativeStartupWriter.class))) {
                transport.set(configuration.aiRuntimeMaterialTransport(material));
                assertThat(transport.get().disabled()).isFalse();
                assertThat(material.isRunning()).isFalse();
                api.status = 500;

                // when
                material.refresh();

                // then
                assertThat(disabledBeforeDatabase.get()).isTrue();
                assertThat(transport.get().disabled()).isTrue();
                assertThat(material.isRunning()).isFalse();
                assertThat(calls).hasValue(2);
                int requestsAfterFailure = api.requests.get();
                api.status = 200;
                material.refresh();
                material.start();
                assertThat(api.requests).hasValue(requestsAfterFailure);
                assertThat(transport.get().disabled()).isTrue();
                verify(startup, times(2)).disableAndConfirm(any(AiRuntimeOperationBudget.class));
            }
        }
    }

    @Test
    void retiresItsOwnedTimer_whenTheActualFiveSecondRefreshFails() throws Exception {
        // given
        Set<Thread> before = materialThreads();
        var returnedDenial = new AtomicBoolean();
        doAnswer(call -> {
            returnedDenial.set(true);
            return null;
        }).when(startup).disableAndConfirm(any());
        try (var api = new Api(directory, false, returnedDenial)) {
            Path bootstrap = api.bootstrap();
            context(bootstrap).run(application -> {
                assertThat(application).hasNotFailed();
                RuntimeProxyTransport transport = application.getBean(RuntimeProxyTransport.class);
                Thread owned = ownedMaterialThread(before);
                assertThat(api.requests.get()).isGreaterThanOrEqualTo(6);
                api.status = 500;

                // when
                assertThat(api.failedRequest.await(7, TimeUnit.SECONDS)).isTrue();

                // then
                await()
                        .pollInSameThread()
                        .atMost(Duration.ofSeconds(1))
                        .untilAsserted(() -> assertThat(transport.disabled()).isTrue());
                await()
                        .pollInSameThread()
                        .atMost(Duration.ofSeconds(2))
                        .untilAsserted(() -> assertThat(owned.isAlive()).isFalse());
                assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                assertThat(api.invalidRequests).hasValue(0);
                verify(startup, times(2)).disableAndConfirm(any(AiRuntimeOperationBudget.class));
            });
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"throwing", "missing", "ambiguous"})
    void refusesValidMaterialBeforeAnyApiRequest_whenDenialCannotBeConfirmed(String mode) throws Exception {
        var returnedDenial = new AtomicBoolean();
        try (var api = new Api(directory, false, returnedDenial)) {
            Path bootstrap = api.bootstrap();
            var selected = new ApplicationContextRunner()
                    .withUserConfiguration(AiRuntimeNativeMaterialConfiguration.class)
                    .withBean("ordinary", String.class, () -> "ordinary")
                    .withPropertyValues("otilm.ai.runtime.native-material-file=" + bootstrap,
                            "server.servlet.context-path=/api");
            var second = mock(AiRuntimeNativeStartupWriter.class);
            if (mode.equals("throwing")) {
                doThrow(new AiRuntimeOperationBudget.Unavailable(false)).when(startup).disableAndConfirm(any());
                selected = selected.withBean(AiRuntimeNativeStartupWriter.class, () -> startup);
            } else if (mode.equals("ambiguous")) {
                selected = selected
                        .withBean("firstDenial", AiRuntimeNativeStartupWriter.class, () -> startup)
                        .withBean("secondDenial", AiRuntimeNativeStartupWriter.class, () -> second);
            }
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                    .getLogger(AiRuntimeNativeMaterialConfiguration.class);
            var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
            events.start();
            logger.addAppender(events);
            try {
                selected.run(application -> {
                    assertThat(application).hasNotFailed();
                    assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                    assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
                    assertThat(application.getBeanProvider(AiRuntimeControllerAuthority.class).getIfUnique()).isNull();
                    assertThat(api.requests).hasValue(0);
                    if (mode.equals("throwing")) {
                        verify(startup).disableAndConfirm(any(AiRuntimeOperationBudget.class));
                    } else {
                        verifyNoInteractions(startup, second);
                    }
                });
                assertThat(events.list)
                        .extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage)
                        .contains("AI runtime native material operation=startup status=UNCONFIRMED")
                        .doesNotContain("AI runtime native material operation=startup status=UNAVAILABLE");
            } finally {
                logger.detachAppender(events);
                events.stop();
            }
        }
    }

    @Test
    void revalidatesExpiredInitialPolicySynchronouslyBeforeTheWebServerLifecycle() throws Exception {
        var returnedDenial = new AtomicBoolean(true);
        try (var api = new Api(directory, false, returnedDenial)) {
            var input = AiRuntimeNativeMaterialFile.read(api.bootstrap(), "/api");
            var instant = new AtomicReference<>(Instant.now());
            var nanos = new AtomicLong();
            Clock clock = new Clock() {
                @Override
                public ZoneId getZone() {
                    return ZoneOffset.UTC;
                }

                @Override
                public Clock withZone(ZoneId zone) {
                    return Clock.fixed(instant(), zone);
                }

                @Override
                public Instant instant() {
                    return instant.get();
                }
            };
            var publisher = new AiRuntimeNativeMaterialPublisher(input.policy(), clock, nanos::get);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            var keys = IdentityFiles
                    .loadServerKeys(input.certificateFile(), input.privateKeyFile(), input.serverCaFile());
            var listeners = input
                    .listeners()
                    .stream()
                    .map(binding -> new RuntimeProxyTransport.Listener(binding.role(), binding.address(),
                            binding.port(), keys, new RuntimeProxyTrustManager(publisher, clock, binding.role())))
                    .toList();
            var transport = RuntimeProxyTransport.forListeners(input.contextPath(), listeners);
            var authority = new AiRuntimeControllerAuthority(input.controller());
            var source = new AiRuntimeControllerServiceImpl.Source(input.observation(), input.workloadProfiles());
            try (var material = new AiRuntimeNativeMaterialConfiguration.Materials(transport, authority, source,
                    publisher, startup)) {
                instant.set(instant.get().plusSeconds(31));
                nanos.set(TimeUnit.SECONDS.toNanos(31));
                assertThat(publisher.get()).isNull();
                assertThat(api.requests).hasValue(3);

                material.start();

                assertThat(publisher.get()).isNotNull();
                assertThat(api.requests).hasValue(6);
                assertThat(transport.disabled()).isFalse();
                assertThat(material.getPhase()).isLessThan(WebServerApplicationContext.START_STOP_LIFECYCLE_PHASE);
            }
            assertThat(transport.disabled()).isTrue();
        }
    }

    @Test
    void disablesBeforeLifecycleStopOnlyForItsOwningContextCloseEvent() throws Exception {
        var returnedDenial = new AtomicBoolean(true);
        try (var api = new Api(directory, false, returnedDenial); var unrelated = new StaticApplicationContext()) {
            Path bootstrap = api.bootstrap();
            context(bootstrap).run(application -> {
                var transport = application.getBean(RuntimeProxyTransport.class);
                var material = application.getBean(AiRuntimeNativeMaterialConfiguration.Materials.class);
                var owner = application.getSourceApplicationContext();
                owner.publishEvent(new ContextClosedEvent(unrelated));
                assertThat(transport.disabled()).isFalse();

                owner.publishEvent(new ContextClosedEvent(owner));

                assertThat(transport.disabled()).isTrue();
                assertThat(material.isRunning()).isFalse();
                int requests = api.requests.get();
                material.start();
                material.refresh();
                assertThat(api.requests).hasValue(requests);
                assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
            });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ApplicationContextRunner context(Path bootstrap) {
        return new ApplicationContextRunner()
                .withUserConfiguration(AiRuntimeNativeMaterialConfiguration.class)
                .withBean("ordinary", String.class, () -> "ordinary")
                .withBean(AiRuntimeNativeStartupWriter.class, () -> startup)
                .withPropertyValues("otilm.ai.runtime.native-material-file=" + bootstrap,
                        "server.servlet.context-path=/api");
    }

    private static Set<Thread> materialThreads() {
        return Thread
                .getAllStackTraces()
                .keySet()
                .stream()
                .filter(thread -> thread.isAlive() && thread.getName().equals(TIMER_NAME))
                .collect(Collectors.toSet());
    }

    private static Thread ownedMaterialThread(Set<Thread> before) {
        var selected = new AtomicReference<Thread>();
        await().pollInSameThread().atMost(Duration.ofSeconds(1)).untilAsserted(() -> {
            Set<Thread> fresh = materialThreads();
            fresh.removeAll(before);
            assertThat(fresh).hasSize(1);
            selected.set(fresh.iterator().next());
        });
        return selected.get();
    }

    /** Synthetic authenticated API and fresh test PKI, never an attestation or a maintained cluster. */
    private static final class Api implements AutoCloseable {
        private static final ObjectMapper JSON = ObjectMapperFactory.aiGatewayWire();
        private static final UUID NAMESPACE_UID = UUID.fromString("588390ce-d2bc-436e-89c5-78ca6abdf1ce");
        private static final UUID CONFIG_UID = UUID.fromString("d55c5775-a4da-483d-b2c7-f96404f98d7c");
        private static final String NAMESPACE_PATH = "/api/v1/namespaces/runtime";
        private static final String POLICY_PATH = NAMESPACE_PATH + "/configmaps/runtime-trust";
        private static final String TOKEN = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGlj";
        private final Path directory;
        private final Path certificate;
        private final Path privateKey;
        private final Path ca;
        private final Path token;
        private final HttpsServer server;
        private final ExecutorService executor = Executors.newFixedThreadPool(2);
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger invalidRequests = new AtomicInteger();
        private final AtomicInteger beforeDenial = new AtomicInteger();
        private final List<String> paths = new CopyOnWriteArrayList<>();
        private final CountDownLatch failedRequest = new CountDownLatch(1);
        private final Map<RuntimePeerRole, Path> profiles;
        private volatile int status = 200;

        private Api(Path directory, boolean clientPurpose, AtomicBoolean returnedDenial) throws Exception {
            this.directory = directory;
            Instant now = Instant.now();
            var authority = issue(null, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, null, null, now.minusSeconds(60),
                    now.plusSeconds(600));
            var apiLeaf = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "native-material.invalid")),
                    now.minusSeconds(30), now.plusSeconds(300));
            var coreLeaf = issue(authority, false, KeyUsage.digitalSignature,
                    clientPurpose ? KeyPurposeId.id_kp_clientAuth : KeyPurposeId.id_kp_serverAuth,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "core.invalid")), now.minusSeconds(30),
                    now.plusSeconds(300));
            certificate = write("core.pem", pem("CERTIFICATE", coreLeaf.certificate().getEncoded())
                    + pem("CERTIFICATE", authority.certificate().getEncoded()));
            privateKey = write("core-key.pem", pem("PRIVATE KEY", coreLeaf.keys().getPrivate().getEncoded()));
            ca = write("ca.pem", pem("CERTIFICATE", authority.certificate().getEncoded()));
            token = write("api-token", TOKEN);
            profiles = Map
                    .of(RuntimePeerRole.RUNNER_PROXY, write("runner.json", "{}"), RuntimePeerRole.GATEWAY_RUN,
                            write("gateway-run.json", "{}"), RuntimePeerRole.GATEWAY_MANAGEMENT,
                            write("gateway-management.json", "{}"));
            ObjectNode namespace = object("Namespace", "runtime", NAMESPACE_UID, "1");
            ObjectNode policy = JSON.createObjectNode().put("version", 1).put("revision", 1);
            policy
                    .putArray("authorities")
                    .addObject()
                    .put("cluster", "lab")
                    .put("certificateDerBase64",
                            Base64.getEncoder().encodeToString(authority.certificate().getEncoded()));
            policy.putArray("deniedTbsFingerprints").add("1".repeat(64));
            ObjectNode configMap = object("ConfigMap", "runtime-trust", CONFIG_UID, "11");
            ((ObjectNode) configMap.get("metadata")).put("namespace", "runtime");
            configMap.putObject("data").put("policy.json", policy.toString());
            var keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("server", apiLeaf.keys().getPrivate(), new char[0], chain(apiLeaf, authority));
            var managers = KeyManagerFactory.getInstance("SunX509");
            managers.init(keys, new char[0]);
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(managers.getKeyManagers(), null, null);
            server = HttpsServer
                    .create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(tls));
            server.setExecutor(executor);
            server.createContext("/", exchange -> {
                try (exchange) {
                    requests.incrementAndGet();
                    if (!returnedDenial.get()) {
                        beforeDenial.incrementAndGet();
                    }
                    String path = exchange.getRequestURI().toString();
                    paths.add(path);
                    boolean authenticated = "GET".equals(exchange.getRequestMethod())
                            && ("Bearer " + TOKEN).equals(exchange.getRequestHeaders().getFirst("Authorization"));
                    if (!authenticated) {
                        invalidRequests.incrementAndGet();
                    }
                    boolean knownPath = NAMESPACE_PATH.equals(path) || POLICY_PATH.equals(path);
                    int response = !authenticated ? 401 : !knownPath ? 404 : status;
                    byte[] body = JSON.writeValueAsBytes(NAMESPACE_PATH.equals(path) ? namespace : configMap);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(response, body.length);
                    exchange.getResponseBody().write(body);
                    if (response == 500) {
                        failedRequest.countDown();
                    }
                }
            });
            server.start();
        }

        private Path bootstrap() throws Exception {
            ObjectNode root = JSON
                    .createObjectNode()
                    .put("version", 1)
                    .put("cluster", "lab")
                    .put("contextPath", "/api");
            root
                    .putObject("serverIdentity")
                    .put("certificateFile", certificate.toString())
                    .put("privateKeyFile", privateKey.toString())
                    .put("serverCaFile", ca.toString());
            int port = 44100;
            for (RuntimePeerRole role : RuntimePeerRole.values()) {
                root
                        .withArray("listeners")
                        .addObject()
                        .put("role", role.name())
                        .put("address", "127.0.0.1")
                        .put("port", ++port);
            }
            ObjectNode policy = root.putObject("policySource");
            policy.set("api", api());
            policy
                    .put("namespaceName", "runtime")
                    .put("namespaceUid", NAMESPACE_UID.toString())
                    .put("configMapName", "runtime-trust")
                    .put("configMapUid", CONFIG_UID.toString());
            root.set("observationSource", api());
            ObjectNode deployment = root.putObject("controllerDeployment");
            deployment
                    .put("namespaceName", "runtime")
                    .put("namespaceUid", NAMESPACE_UID.toString())
                    .put("serviceAccountName", "controller")
                    .put("serviceAccountUid", UUID.randomUUID().toString())
                    .put("jobName", "controller")
                    .put("jobUid", UUID.randomUUID().toString())
                    .put("podName", "controller-a")
                    .put("podUid", UUID.randomUUID().toString())
                    .put("runtimeClass", "sandbox")
                    .put("runtimeUid", UUID.randomUUID().toString())
                    .put("runtimeHandler", "sandbox")
                    .put("schedulingGate", "ilm.example/ready")
                    .put("podSpecJson", "{}")
                    .put("jobSpecJson", "{}")
                    .put("runtimeConfigurationJson", "{}")
                    .put("podMetadataJson", "{}");
            deployment.putObject("imageIds").put("controller", "docker-pullable://controller@sha256:" + "a".repeat(64));
            ObjectNode profileFiles = root.putObject("workloadProfiles");
            profiles.forEach((role, file) -> profileFiles.put(role.name(), file.toString()));
            return write("bootstrap.json", root.toString());
        }

        private ObjectNode api() {
            return JSON
                    .createObjectNode()
                    .put("origin", origin())
                    .put("address", "127.0.0.1")
                    .put("serverCaFile", ca.toString())
                    .put("tokenFile", token.toString());
        }

        private String origin() {
            return "https://native-material.invalid:" + server.getAddress().getPort();
        }

        private Path write(String name, String text) throws Exception {
            Path file = directory.resolve(name);
            Files.writeString(file, text, StandardCharsets.US_ASCII);
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            return file;
        }

        private static String pem(String label, byte[] bytes) {
            return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                    + "\n-----END " + label + "-----\n";
        }

        private static ObjectNode object(String kind, String name, UUID uid, String resourceVersion) {
            ObjectNode result = JSON.createObjectNode().put("apiVersion", "v1").put("kind", kind);
            result
                    .putObject("metadata")
                    .put("name", name)
                    .put("uid", uid.toString())
                    .put("resourceVersion", resourceVersion);
            return result;
        }

        @Override
        public void close() throws Exception {
            server.stop(0);
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }
}
