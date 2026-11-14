package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.model.ai.AiRuntimeGatewayState;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.security.ai.AiRuntimeControllerAuthority;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeNativeMaterialPublisher;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Real policy and role-profile/API observations over mocked short DB/native-peer boundaries; not live attestation. */
public class AiRuntimeControllerRegistrationServiceTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void onlyCurrentActualOwnProfilePublishesIntoItsIndependentTypedRegistry(boolean management) throws Exception {
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            var reply = fixture.observe(management);
            if (!reply.getStatusCode().is2xxSuccessful()) {
                verify(fixture.runWriter, org.mockito.Mockito.never()).observe(any(), any());
                verify(fixture.managementWriter, org.mockito.Mockito.never()).observe(any(), any());
                fixture.noImplicitConfigurationOrEnable();
            }
            assertThat(reply.getStatusCode().value()).isEqualTo(200);
            if (management) {
                var captured = ArgumentCaptor.forClass(AiRuntimeManagementGatewayState.Observation.class);
                verify(fixture.managementWriter).observe(captured.capture(), any());
                assertThat(captured.getValue().subject().podUid()).isEqualTo(fixture.managementPod);
                assertThat(captured.getValue().subject().serviceAccount()).isEqualTo("gateway-management");
                assertThat(captured.getValue().deployment().revision()).isEqualTo(12);
                verifyNoInteractions(fixture.runWriter);
            } else {
                var captured = ArgumentCaptor.forClass(AiRuntimeGatewayState.Observation.class);
                verify(fixture.runWriter).observe(captured.capture(), any());
                assertThat(captured.getValue().subject().podUid()).isEqualTo(fixture.runPod);
                assertThat(captured.getValue().subject().serviceAccount()).isEqualTo("gateway-run");
                assertThat(captured.getValue().deployment().controlGeneration()).isEqualTo(2);
                verifyNoInteractions(fixture.managementWriter);
            }
            verify(fixture.authority, org.mockito.Mockito.times(2)).requireCurrent(any(), any());
            assertThat(fixture.api.requests.get() - fixture.policyRequests).isGreaterThanOrEqualTo(11);
            fixture.noImplicitConfigurationOrEnable();
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void anotherRoleProfileCannotBecomeTheConfiguredGatewayBySelectingItsSlot(boolean management) throws Exception {
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            Files.write(fixture.file(management), Files.readAllBytes(fixture.file(!management)));
            assertThat(fixture.observe(management).getStatusCode().is2xxSuccessful()).isFalse();
            fixture.noObservation();
            assertThat(fixture.api.requests).hasValue(fixture.policyRequests);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void losingCurrentPolicyDuringTheActualApiObservationCannotPublish(boolean management) throws Exception {
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            fixture.onPodRead.set(fixture.policy::close);
            assertThat(fixture.observe(management).getStatusCode().value()).isEqualTo(503);
            fixture.noObservation();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void changedAcceptedRecipeOrStoredDeploymentAfterApiObservationCannotPublish(boolean management) throws Exception {
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            fixture.onPodRead.set(() -> {
                try {
                    Files.writeString(fixture.file(management), "{}");
                } catch (Exception failure) {
                    throw new AssertionError(failure);
                }
            });
            assertThat(fixture.observe(management).getStatusCode().is2xxSuccessful()).isFalse();
            fixture.noObservation();
        }
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            fixture.onPodRead.set(() -> {
                if (management) {
                    var old = fixture.managementDeployment.get();
                    fixture.managementDeployment.set(new AiRuntimeManagementGatewayState.Deployment(13, old.pins()));
                } else {
                    var old = fixture.runDeployment.get();
                    fixture.runDeployment
                            .set(new AiRuntimeGatewayState.Deployment(old.role(), 3, old.imageDigest(), old.launch()));
                }
            });
            assertThat(fixture.observe(management).getStatusCode().is2xxSuccessful()).isFalse();
            fixture.noObservation();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void missingConfigurationAndSpentOriginalBudgetNeverCallAnObservationWriter(boolean management) throws Exception {
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            if (management) {
                when(fixture.managementWriter.deployment(any())).thenReturn(Optional.empty());
            } else {
                when(fixture.runWriter.deployment(any())).thenReturn(Optional.empty());
            }
            assertThat(fixture.observe(management).getStatusCode().value()).isEqualTo(403);
            fixture.noObservation();
        }
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));
            fixture.onPodRead.set(() -> fixture.nanos.set(5_000_000_000L));
            assertThat(fixture.observe(management).getStatusCode().value()).isEqualTo(503);
            fixture.noObservation();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void refreshesTrustedGatewayEvidence_whenNewExecutionIsDisabled(boolean management) throws Exception {
        // given
        var disabled = new AiFeatureGate(false);
        try (var fixture = new Fixture(directory); var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(fixture.controller));

            // when
            var reply = fixture.observe(management);

            // then
            assertThat(reply.getStatusCode().value()).isEqualTo(200);
            if (management) {
                verify(fixture.managementWriter).observe(any(), any());
                verifyNoInteractions(fixture.runWriter);
            } else {
                verify(fixture.runWriter).observe(any(), any());
                verifyNoInteractions(fixture.managementWriter);
            }
            verify(fixture.authority, org.mockito.Mockito.times(2)).requireCurrent(any(), any());
            fixture.noImplicitConfigurationOrEnable();
            var gateway = fixture.gatewayPeer(management);
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(gateway));
            var run = new AiRuntimeGatewayServiceImpl(new AiRuntimeGatewayAuthority(fixture.runWriter),
                    mock(AiModelRunDispatchService.class), mock(AiModelRunOutcomeWriter.class), disabled);
            var mgt = new AiRuntimeManagementGatewayServiceImpl(
                    new AiRuntimeManagementGatewayAuthority(fixture.managementWriter),
                    mock(AiModelManagementDispatchService.class), mock(AiModelManagementGatewayWriter.class),
                    mock(AiModelManagementOutcomeWriter.class), disabled);
            var registration = management ? mgt.registration() : run.registration();
            assertThat(registration.getStatusCode().value()).isEqualTo(200);
            var document = ObjectMapperFactory.aiGatewayWire().readTree(registration.getBody());
            assertThat(document.path("kind").asText())
                    .isEqualTo(management
                            ? "management-gateway-registration-pending"
                            : "run-gateway-registration-pending");
            verify(fixture.runWriter, never()).current(any(), any());
            verify(fixture.managementWriter, never()).current(any(), any());
        }
    }

    public static final class Fixture implements AutoCloseable {
        private static final com.fasterxml.jackson.databind.ObjectMapper JSON = ObjectMapperFactory.aiKubernetesWire();
        private static final String NS = "77bd9027-9e2a-43b4-890f-a36eb970ae46";
        private static final UUID CONFIG = UUID.fromString("51fd9d23-03ce-4d1c-a4cc-ecf095e381a4");
        private final Instant now = Instant.now();
        private final AtomicLong nanos = new AtomicLong();
        private final UUID runPod = UUID.fromString("408419f6-39b8-4636-9c6f-a93a6a886bed");
        private final UUID managementPod = UUID.fromString("800af6a4-86ef-41ed-9be4-1174b75f06e8");
        private final AiRuntimeControllerAuthority authority = mock(AiRuntimeControllerAuthority.class);
        private final AiRuntimeGatewayRegistrationWriter runWriter;
        private final AiRuntimeManagementGatewayWriter managementWriter;
        private final RuntimePeer controller = new RuntimePeer(RuntimePeerRole.CONTROLLER,
                new RuntimeProxyCertificateClaims("lab", "runtime", "controller", "controller-one", UUID.randomUUID()));
        private final AtomicReference<AiRuntimeGatewayState.Deployment> runDeployment = new AtomicReference<>();
        private final AtomicReference<AiRuntimeManagementGatewayState.Deployment> managementDeployment = new AtomicReference<>();
        private final AtomicReference<Runnable> onPodRead = new AtomicReference<>();
        private final Map<RuntimePeerRole, Path> files = new EnumMap<>(RuntimePeerRole.class);
        private final Map<String, ObjectNode> jobs = new java.util.HashMap<>();
        private final Map<String, ObjectNode> pods = new java.util.HashMap<>();
        private final Map<String, String> accounts = new java.util.HashMap<>();
        private final ControllerServiceApiFixture api;
        private final AiRuntimeNativeMaterialPublisher policy;
        private final AiRuntimeControllerRegistrationServiceImpl service;
        private final int policyRequests;

        private Fixture(Path directory) throws Exception {
            this(directory, mock(AiRuntimeGatewayRegistrationWriter.class),
                    mock(AiRuntimeManagementGatewayWriter.class));
            when(runWriter.deployment(any())).thenAnswer(call -> Optional.of(runDeployment.get()));
            when(managementWriter.deployment(any())).thenAnswer(call -> Optional.of(managementDeployment.get()));
            when(runWriter.nextObservationSequence(anyLong(), any())).thenReturn(5L);
            when(managementWriter.nextObservationSequence(anyLong(), any())).thenReturn(9L);
            when(runWriter.observe(any(), any())).thenReturn(true);
            when(managementWriter.observe(any(), any()))
                    .thenReturn(AiRuntimeState.Transition.empty(AiRuntimeState.Status.APPLIED));
        }

        public Fixture(Path directory, AiRuntimeGatewayRegistrationWriter runWriter,
                AiRuntimeManagementGatewayWriter managementWriter) throws Exception {
            this.runWriter = runWriter;
            this.managementWriter = managementWriter;
            api = new ControllerServiceApiFixture(directory);
            byte[] template;
            try (var input = AiRuntimeControllerRegistrationServiceTest.class
                    .getResourceAsStream("/ai/controller-service-profile.json")) {
                template = java.util.Objects.requireNonNull(input).readAllBytes();
            }
            Path runner = Files.createTempFile(directory, "unused-runner-profile-", ".json");
            Files.write(runner, template);
            Files.setPosixFilePermissions(runner, PosixFilePermissions.fromString("rw-------"));
            files.put(RuntimePeerRole.RUNNER_PROXY, runner);
            var runPins = roleProfile(directory, template, false);
            var managementPins = roleProfile(directory, template, true);
            runDeployment
                    .set(new AiRuntimeGatewayState.Deployment(RuntimePeerRole.GATEWAY_RUN, 2,
                            "sha256:" + "a".repeat(64), runPins));
            managementDeployment
                    .set(new AiRuntimeManagementGatewayState.Deployment(12,
                            new AiRuntimeManagementGatewayState.Pins("sha256:" + "e".repeat(64), managementPins)));
            String root = Base64.getEncoder().encodeToString(Files.readAllBytes(api.configuration().serverCaFile()));
            api.responder = path -> response(path, root);
            policy = new AiRuntimeNativeMaterialPublisher(
                    new AiRuntimeNativeMaterialPublisher.Source(api.configuration(), "runtime", UUID.fromString(NS),
                            "policy", CONFIG),
                    Clock.fixed(now, ZoneOffset.UTC));
            policy.refresh(AiRuntimeOperationBudget.start());
            assertThat(api.failure.get()).isNull();
            assertThat(policy.current()).isPresent();
            policyRequests = api.requests.get();
            var source = new AiRuntimeControllerServiceImpl.Source(api.configuration(), files);
            var beans = new StaticListableBeanFactory(
                    Map.of("authority", authority, "source", source, "policy", policy));
            service = new AiRuntimeControllerRegistrationServiceImpl(
                    beans.getBeanProvider(AiRuntimeControllerAuthority.class),
                    beans.getBeanProvider(AiRuntimeControllerServiceImpl.Source.class),
                    beans.getBeanProvider(AiRuntimeNativeMaterialPublisher.class), runWriter, managementWriter,
                    Clock.fixed(now, ZoneOffset.UTC), nanos::get);
        }

        private AiRuntimeState.LaunchSpec roleProfile(Path directory, byte[] template, boolean management)
                throws Exception {
            String name = management ? "gateway-management" : "gateway-run";
            String account = management
                    ? "42f4a9bd-dfda-4a14-9891-2bff5fd78755"
                    : "f520b467-e75e-4b51-9579-d9af91d683aa";
            String jobUid = management
                    ? "ea1bbb4c-a3b6-473d-b625-113f530aa024"
                    : "736947e7-2778-4b40-8b0b-a514e319113c";
            UUID podUid = management ? managementPod : runPod;
            String image = "sha256:" + (management ? "e" : "a").repeat(64);
            String observedImage = "containerd://sha256:" + (management ? "f" : "c").repeat(64);
            var document = (ObjectNode) JSON.readTree(template);
            ((ObjectNode) document.path("pins"))
                    .put("serviceAccountName", name)
                    .put("serviceAccountUid", account)
                    .put("imageDigest", image);
            var spec = (ObjectNode) document.path("podSpec");
            spec.put("serviceAccountName", name);
            ((ObjectNode) spec.path("containers").get(0))
                    .put("name", "gateway")
                    .put("image", "local.invalid/" + name + "@" + image);
            ((ObjectNode) spec.path("containers").get(0))
                    .putArray("command")
                    .add("/opt/java/openjdk/bin/java")
                    .add(management
                            ? "com.otilm.ai.gateway.GatewayManagementMain"
                            : "com.otilm.ai.gateway.GatewayRunMain");
            ((ObjectNode) document.path("job").path("metadata")).put("name", name);
            var roleLabels = JSON.createObjectNode().put("ilm.otilm.ai/role", name);
            ((ObjectNode) document.path("job").path("spec").path("selector")).set("matchLabels", roleLabels.deepCopy());
            ((ObjectNode) document.path("job").path("spec").path("template").path("metadata"))
                    .set("labels", roleLabels.deepCopy());
            ((ObjectNode) document.path("podMetadata")).set("labels", roleLabels.deepCopy());
            ((ObjectNode) document.path("job").path("spec").path("template")).set("spec", spec.deepCopy());
            ((ObjectNode) document.path("imageIds")).removeAll().put("gateway", observedImage);
            Path file = Files.createTempFile(directory, name + "-", ".json");
            Files.write(file, JSON.writeValueAsBytes(document));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            files.put(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN, file);
            var job = ((ObjectNode) document.path("job")).deepCopy();
            ((ObjectNode) job.path("metadata")).put("uid", jobUid).put("resourceVersion", "job-rv");
            jobs.put(name, job);
            var pod = object("v1", "Pod", name + "-one", podUid.toString(), true);
            ((ObjectNode) pod.path("metadata")).set("labels", document.path("podMetadata").path("labels"));
            ((ObjectNode) pod.path("metadata"))
                    .putArray("ownerReferences")
                    .addObject()
                    .put("apiVersion", "batch/v1")
                    .put("kind", "Job")
                    .put("name", name)
                    .put("uid", jobUid)
                    .put("controller", true);
            var actual = spec.deepCopy();
            actual.remove("schedulingGates");
            actual.put("nodeName", "synthetic-node");
            pod.set("spec", actual);
            pod
                    .putObject("status")
                    .put("phase", "Running")
                    .putArray("containerStatuses")
                    .addObject()
                    .put("name", "gateway")
                    .put("restartCount", 0)
                    .put("ready", true)
                    .put("started", true)
                    .put("imageID", observedImage)
                    .put("containerID", "containerd://" + (management ? "8" : "9").repeat(64))
                    .putObject("state")
                    .putObject("running");
            pods.put(name + "-one", pod);
            accounts.put(name, account);
            return new AiRuntimeState.LaunchSpec("lab", "runtime", NS, name, account, "sha256:" + "b".repeat(64),
                    "ilm-runsc");
        }

        private ControllerServiceApiFixture.Reply response(String path, String root) {
            try {
                ObjectNode body;
                if (path.equals("/api/v1/namespaces/runtime")) {
                    body = object("v1", "Namespace", "runtime", NS, false);
                } else if (path.equals("/api/v1/namespaces/runtime/configmaps/policy")) {
                    body = object("v1", "ConfigMap", "policy", CONFIG.toString(), true);
                    var content = JSON.createObjectNode().put("version", 1).put("revision", 13);
                    content.putArray("authorities").addObject().put("cluster", "lab").put("certificateDerBase64", root);
                    content.putArray("deniedTbsFingerprints");
                    body.putObject("data").put("policy.json", JSON.writeValueAsString(content));
                } else if (path.startsWith("/apis/batch/v1/namespaces/runtime/jobs/")) {
                    body = jobs.get(path.substring(path.lastIndexOf('/') + 1));
                } else if (path.equals("/api/v1/namespaces/runtime/pods")) {
                    body = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
                    body.putObject("metadata").put("resourceVersion", "list-rv");
                    var rows = body.putArray("items");
                    pods.values().forEach(rows::add);
                } else if (path.startsWith("/api/v1/namespaces/runtime/pods/")) {
                    body = pods.get(path.substring(path.lastIndexOf('/') + 1));
                    Runnable hook = onPodRead.getAndSet(null);
                    if (hook != null) {
                        hook.run();
                    }
                } else if (path.startsWith("/api/v1/namespaces/runtime/serviceaccounts/")) {
                    String name = path.substring(path.lastIndexOf('/') + 1);
                    body = object("v1", "ServiceAccount", name, accounts.get(name), true);
                } else if (path.equals("/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc")) {
                    body = object("node.k8s.io/v1", "RuntimeClass", "ilm-runsc", "bb92d9d9-796b-427e-9e29-daa69c8a061b",
                            false);
                    body.put("handler", "runsc");
                } else {
                    throw new AssertionError("Unexpected synthetic role observation path");
                }
                return new ControllerServiceApiFixture.Reply(200, JSON.writeValueAsBytes(body));
            } catch (Exception invalid) {
                throw new AssertionError(invalid);
            }
        }

        private static ObjectNode object(String version, String kind, String name, String uid, boolean namespaced) {
            var body = JSON.createObjectNode().put("apiVersion", version).put("kind", kind);
            var metadata = body.putObject("metadata").put("name", name).put("uid", uid).put("resourceVersion", "rv");
            if (namespaced) {
                metadata.put("namespace", "runtime");
            }
            return body;
        }

        private Path file(boolean management) {
            return files.get(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN);
        }

        public ResponseEntity<byte[]> observe(boolean management) {
            return management ? service.observeManagementGateway() : service.observeRunGateway();
        }

        public void configureRegistries() {
            assertThat(runWriter.configure(runDeployment.get(), AiRuntimeOperationBudget.start())).isTrue();
            var configured = managementWriter
                    .configure(0, managementDeployment.get().pins(), AiRuntimeOperationBudget.start());
            assertThat(configured.status()).isEqualTo(AiRuntimeState.Status.APPLIED);
            managementDeployment.set(configured.value().orElseThrow());
        }

        public AiRuntimeGatewayState.Deployment runDeployment() {
            return runDeployment.get();
        }

        public AiRuntimeManagementGatewayState.Deployment managementDeployment() {
            return managementDeployment.get();
        }

        public RuntimePeer gatewayPeer(boolean management) {
            var launch = management ? managementDeployment.get().pins().launch() : runDeployment.get().launch();
            String name = management ? "gateway-management-one" : "gateway-run-one";
            UUID pod = management ? managementPod : runPod;
            return new RuntimePeer(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN,
                    new RuntimeProxyCertificateClaims(launch.cluster(), launch.namespaceName(),
                            launch.serviceAccountName(), name, pod));
        }

        public RuntimePeer controllerPeer() {
            return controller;
        }

        private void noImplicitConfigurationOrEnable() {
            verify(runWriter, never()).configure(any(), any());
            verify(managementWriter, never()).configure(anyLong(), any(), any());
        }

        private void noObservation() {
            verify(runWriter, never()).observe(any(), any());
            verify(managementWriter, never()).observe(any(), any());
            noImplicitConfigurationOrEnable();
        }

        @Override
        public void close() throws Exception {
            policy.close();
            api.close();
        }
    }
}
