package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Synthetic API objects test identity/profile comparison, not native attestation or business authority. */
class KubernetesSnapshotVerifierTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String NS_UID = "2c00c948-93bd-4855-91de-2bf45752fd8e";
    private static final String SA_UID = "a579fa43-e42f-4975-a093-5c3b26a91ea3";
    private static final String JOB_UID = "b97c4892-455d-4708-b843-85c974ed4a30";
    private static final String POD_UID = "41093c61-3bc3-427d-8a53-69faea046b58";
    private static final String IMAGE = "sha256:" + "a".repeat(64);
    private static final String GATE = "ilm.otilm.ai/runtime-eligible";
    private static final String SPEC = """
            {"serviceAccountName":"runner","automountServiceAccountToken":false,
             "runtimeClassName":"ilm-runsc","restartPolicy":"Never",
             "schedulingGates":[{"name":"ilm.otilm.ai/runtime-eligible"}],
             "securityContext":{"runAsNonRoot":true,"supplementalGroupsPolicy":"Strict"},
             "containers":[{"name":"runner","image":"sha256:%s",
               "command":["/opt/java/openjdk/bin/java","-jar","/opt/runner/fixed.jar"],
               "securityContext":{"runAsUser":65532,"runAsGroup":65532,
                 "allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true}}]}
            """.formatted("a".repeat(64));
    private static final String JOB_SPEC = "{\"template\":{\"spec\":" + SPEC + "}}";

    @Test
    void gatedObservationUsesActualUidsAndResourceVersionWithoutClaimingReadiness() throws Exception {
        var f = new Fixture();
        var o = assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        assertEquals(POD_UID, o.podUid());
        assertEquals(JOB_UID, o.jobUid());
        assertEquals("pod-rv-7", o.podResourceVersion());
        assertEquals(KubernetesSnapshotVerifier.Stage.GATED, o.stage());
    }

    @Test
    void copiedNamesAndLabelsCannotReplaceActualNamespaceAccountJobOrPodUid() throws Exception {
        for (String resource : new String[]{"namespace", "account", "job", "pod"}) {
            var f = new Fixture();
            f.replace(resource, "/metadata/uid", "799217fb-3fd3-4c01-8319-03792742cd96");
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void ownerReferenceMustBeTheActualExpectedControllingJob() throws Exception {
        for (String field : new String[]{"uid", "name", "kind", "apiVersion"}) {
            var f = new Fixture();
            f.replace("pod", "/metadata/ownerReferences/0/" + field, "wrong");
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
        var f = new Fixture();
        f.replace("pod", "/metadata/ownerReferences/0/controller", false);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void deletingObjectsAreNeverObservedAsEligible() throws Exception {
        for (String resource : new String[]{"namespace", "account", "job", "pod", "runtime"}) {
            var f = new Fixture();
            f.put(resource, "/metadata", "deletionTimestamp", "2026-11-06T00:00:00Z");
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void runtimeHandlerAndClosedPodSpecMustMatchTheAcceptedPins() throws Exception {
        var handler = new Fixture();
        handler.replace("runtime", "/handler", "runc");
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyEligible(handler.pins(), handler.namespace, handler.account, handler.job, handler.pod,
                                handler.runtime));
        for (String field : new String[]{"serviceAccountName", "runtimeClassName", "restartPolicy"}) {
            var f = new Fixture();
            f.replace("pod", "/spec/" + field, "wrong");
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
        var token = new Fixture();
        token.replace("pod", "/spec/automountServiceAccountToken", true);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(token.pins(), token.namespace, token.account, token.job, token.pod, token.runtime));
        var extra = new Fixture();
        extra.put("pod", "/spec", "hostPID", true);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(extra.pins(), extra.namespace, extra.account, extra.job, extra.pod, extra.runtime));
    }

    @Test
    void replacingRuntimeClassCannotReuseItsCopiedNameAndHandler() throws Exception {
        var f = new Fixture();
        f.replace("runtime", "/metadata/uid", "799217fb-3fd3-4c01-8319-03792742cd96");
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void changingTheJobTemplateCannotRetainAnOtherwiseMatchingPodObservation() throws Exception {
        var f = new Fixture();
        f.put("job", "/spec", "template", Map.of("spec", Map.of("hostPID", true)));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void acceptedSpecsMustUseTheSameServiceAccountAndRuntimeIdentityAsTheVerifiedObjects() throws Exception {
        for (String[] replacement : new String[][]{{"runner", "different"}, {"ilm-runsc", "other-runtime"}}) {
            var f = new Fixture();
            f.expectedSpec = SPEC.replace("\"" + replacement[0] + "\"", "\"" + replacement[1] + "\"");
            f.put("pod", "", "spec", JSON.readTree(f.expectedSpec));
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void independentlyPinnedJobAndPodSpecsCannotDescribeDifferentTemplates() throws Exception {
        var f = new Fixture();
        f.expectedJobSpec = "{\"template\":{\"spec\":" + SPEC.replace("65532", "65533") + "}}";
        f.put("job", "", "spec", JSON.readTree(f.expectedJobSpec));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void nonUtf8ApiJsonCannotBypassTheWireEncodingContract() throws Exception {
        var f = new Fixture();
        f.namespace = new String(f.namespace, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_16);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void runtimeAdmissionConfigurationMustMatchItsAcceptedProfile() throws Exception {
        var f = new Fixture();
        f.put("runtime", "", "overhead", Map.of("podFixed", Map.of("memory", "1Gi")));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void unapprovedPodAnnotationsCannotChangeTheRuntimeProfile() throws Exception {
        var f = new Fixture();
        f.put("pod", "/metadata", "annotations", Map.of("runtime.example/privileged-mode", "enabled"));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void theFullLegalQualifiedAnnotationNameStillMatchesTheIndependentAcceptedProfile() throws Exception {
        String key = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61) + "/"
                + "e".repeat(63);
        assertEquals(317, key.length());
        var f = new Fixture();
        var metadata = JSON.createObjectNode();
        metadata.putObject("labels");
        metadata.putObject("annotations").put(key, "accepted-public-profile");
        f.expectedMetadata = JSON.writeValueAsString(metadata);
        f.put("pod", "/metadata", "annotations", Map.of(key, "accepted-public-profile"));
        assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void oversizedApiPropertyNamesCannotConsumeTheWholeJsonBodyBudget() {
        byte[] input = ("{\"" + "a".repeat(513) + "\":0}").getBytes(StandardCharsets.UTF_8);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier.parse(input));
    }

    @Test
    void admissionDefaultsRemainIndependentlyPinnedFromTheJobTemplate() throws Exception {
        var f = new Fixture();
        var admitted = (ObjectNode) JSON.readTree(SPEC);
        admitted.put("priority", 0).put("preemptionPolicy", "PreemptLowerPriority");
        admitted
                .set("tolerations", JSON
                        .readTree(
                                """
                                        [{"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},
                                         {"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}]
                                        """));
        f.expectedSpec = JSON.writeValueAsString(admitted);
        f.put("pod", "", "spec", admitted);
        assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        f.replace("pod", "/spec/priority", 1000);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void eligibilityRequiresTheExactApprovedGateAndNoPrematureScheduling() throws Exception {
        var gate = new Fixture();
        gate.replace("pod", "/spec/schedulingGates/0/name", "different-gate");
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(gate.pins(), gate.namespace, gate.account, gate.job, gate.pod, gate.runtime));
        var scheduled = new Fixture();
        scheduled.put("pod", "/spec", "nodeName", "node-one");
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyEligible(scheduled.pins(), scheduled.namespace, scheduled.account, scheduled.job,
                                scheduled.pod, scheduled.runtime));
    }

    @Test
    void runningObservationRequiresReleasedGateZeroRestartsAndExactActualImageId() throws Exception {
        var f = new Fixture();
        f.running();
        var o = assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        assertEquals(KubernetesSnapshotVerifier.Stage.RUNNING, o.stage());
        assertEquals("node-one", o.nodeName());
        var restarted = new Fixture();
        restarted.running();
        restarted.replace("pod", "/status/containerStatuses/0/restartCount", 1);
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyRunning(restarted.pins(), restarted.namespace, restarted.account, restarted.job,
                                restarted.pod, restarted.runtime));
        var image = new Fixture();
        image.running();
        image.replace("pod", "/status/containerStatuses/0/imageID", "sha256:" + "b".repeat(64));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(image.pins(), image.namespace, image.account, image.job, image.pod, image.runtime));
    }

    @Test
    void pendingOrStillGatedPodNeverBecomesARunningObservation() throws Exception {
        var f = new Fixture();
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        f.running();
        f.replace("pod", "/status/phase", "Pending");
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void malformedDuplicateTrailingAndOversizedJsonFailClosed() throws Exception {
        for (String bad : new String[]{
                "{",
                "{} {}",
                "{\"kind\":\"Namespace\",\"kind\":\"Namespace\"}",
                " ".repeat(1_048_577)}) {
            var f = new Fixture();
            f.namespace = bad.getBytes(StandardCharsets.UTF_8);
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void largeRestartCountsCannotWrapToZero() throws Exception {
        var restart = new Fixture();
        restart.running();
        restart
                .replace("pod", "/status/containerStatuses/0/restartCount",
                        new java.math.BigInteger("18446744073709551616"));
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyRunning(restart.pins(), restart.namespace, restart.account, restart.job, restart.pod,
                                restart.runtime));
    }

    @Test
    void terminalJobConditionsCannotPublishANewWorkloadObservation() throws Exception {
        for (String type : new String[]{"Failed", "Complete", "FailureTarget", "SuccessCriteriaMet"}) {
            var f = new Fixture();
            f.put("job", "/status", "conditions", JSON.readTree("""
                    [{"type":"%s","status":"True"}]
                    """.formatted(type)));
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void directoryInitMustHaveExitedZeroAndRestartableProxyMustStillBeRunning() throws Exception {
        var f = new Fixture();
        f.initialContainers();
        f.running();
        assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        for (String state : new String[]{"waiting", "terminated"}) {
            var bad = new Fixture();
            bad.initialContainers();
            bad.running();
            bad.replace("pod", "/status/initContainerStatuses/1/state", JSON.readTree("{\"" + state + "\":{}}"));
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyRunning(bad.pins(), bad.namespace, bad.account, bad.job, bad.pod, bad.runtime));
        }
        var failedInit = new Fixture();
        failedInit.initialContainers();
        failedInit.running();
        failedInit.replace("pod", "/status/initContainerStatuses/0/state/terminated/exitCode", 1);
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyRunning(failedInit.pins(), failedInit.namespace, failedInit.account, failedInit.job,
                                failedInit.pod, failedInit.runtime));
    }

    @Test
    void largeInitExitCodeCannotWrapToASuccessfulExit() throws Exception {
        var f = new Fixture();
        f.initialContainers();
        f.running();
        f
                .replace("pod", "/status/initContainerStatuses/0/state/terminated/exitCode",
                        new java.math.BigInteger("18446744073709551616"));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void actualResourceKindVersionScopeAndResourceVersionCannotBeSubstituted() throws Exception {
        for (String resource : new String[]{"namespace", "account", "job", "pod", "runtime"}) {
            for (String pointer : new String[]{"/apiVersion", "/kind", "/metadata/name", "/metadata/resourceVersion"}) {
                var f = new Fixture();
                f.replace(resource, pointer, pointer.endsWith("resourceVersion") ? "" : "wrong");
                assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                        .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
            }
        }
        for (String resource : new String[]{"account", "job", "pod"}) {
            var f = new Fixture();
            f.replace(resource, "/metadata/namespace", "foreign");
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyEligible(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
        var cluster = new Fixture();
        cluster.put("runtime", "/metadata", "namespace", "foreign");
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyEligible(cluster.pins(), cluster.namespace, cluster.account, cluster.job, cluster.pod,
                                cluster.runtime));
    }

    @Test
    void runningStatusRequiresExactContainerSetAndStrictScalarTypes() throws Exception {
        for (Object count : new Object[]{"0", false, -1, 0.0}) {
            var f = new Fixture();
            f.running();
            f.replace("pod", "/status/containerStatuses/0/restartCount", count);
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
        for (String field : new String[]{"started", "ready"}) {
            for (Object value : new Object[]{false, "true"}) {
                var f = new Fixture();
                f.running();
                f.replace("pod", "/status/containerStatuses/0/" + field, value);
                assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                        .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
            }
        }
        for (Object rows : new Object[]{
                JSON.readTree("[]"),
                JSON.readTree("{}"),
                JSON.readTree("[{\"name\":\"foreign\",\"restartCount\":0}]")}) {
            var f = new Fixture();
            f.running();
            f.put("pod", "/status", "containerStatuses", rows);
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        }
    }

    @Test
    void ambiguousOwnersAndContainerStatesAreDenied() throws Exception {
        var owner = new Fixture();
        owner.put("pod", "/metadata", "ownerReferences", JSON.readTree("[]"));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(owner.pins(), owner.namespace, owner.account, owner.job, owner.pod, owner.runtime));
        var state = new Fixture();
        state.running();
        state.replace("pod", "/status/containerStatuses/0/state", JSON.readTree("{\"running\":{},\"waiting\":{}}"));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(state.pins(), state.namespace, state.account, state.job, state.pod, state.runtime));
        var absent = new Fixture();
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(null, absent.namespace, absent.account, absent.job, absent.pod, absent.runtime));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(absent.pins(), null, absent.account, absent.job, absent.pod, absent.runtime));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyEligible(absent.pins(), new byte[0], absent.account, absent.job, absent.pod, absent.runtime));
        assertEquals("OBSERVATION_UNAVAILABLE", new ObservationFailure().getMessage());
        assertEquals(null, new ObservationFailure().getCause());
    }

    @Test
    void invalidAdministrativePinsCannotConstructApiPathsOrUnboundedContainerSets() {
        for (String name : new String[]{null, "../runtime", "runtime?watch=true", "runtime\r\nAuthorization:x"}) {
            assertThrows(ObservationFailure.class, () -> pins(name, NS_UID, GATE, SPEC, Map.of("runner", IMAGE)));
        }
        for (String uid : new String[]{null, "copied", NS_UID.toUpperCase(java.util.Locale.ROOT)}) {
            assertThrows(ObservationFailure.class, () -> pins("runtime", uid, GATE, SPEC, Map.of("runner", IMAGE)));
        }
        for (String gate : new String[]{null, "no-qualified-prefix", "x".repeat(317)}) {
            assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, gate, SPEC, Map.of("runner", IMAGE)));
        }
        assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, GATE, null, Map.of("runner", IMAGE)));
        assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, GATE, SPEC, null));
        assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, GATE, SPEC, Map.of()));
        assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, GATE, SPEC, Map.of("../runner", IMAGE)));
        assertThrows(ObservationFailure.class,
                () -> pins("runtime", NS_UID, GATE, SPEC, Map.of("runner", "copied-image-name")));
        var excessive = new java.util.LinkedHashMap<String, String>();
        for (int i = 0; i < 17; i++) {
            excessive.put("runner-" + i, IMAGE);
        }
        assertThrows(ObservationFailure.class, () -> pins("runtime", NS_UID, GATE, SPEC, excessive));
    }

    @Test
    void changingTheInputMapCannotChangeTheCapturedImagePins() {
        var images = new java.util.HashMap<>(Map.of("runner", IMAGE));
        var p = pins("runtime", NS_UID, GATE, SPEC, images);
        images.put("runner", "sha256:" + "b".repeat(64));
        assertEquals(IMAGE, p.imageIds().get("runner"));
        assertThrows(UnsupportedOperationException.class, () -> p.imageIds().put("extra", IMAGE));
    }

    @Test
    void declaredImageReferenceAndObservedRuntimeIdentityAreIndependentlyPinned() throws Exception {
        var f = new Fixture();
        String declared = "registry.invalid/ilm/runner@" + IMAGE;
        String actualImageId = "containerd://sha256:" + "d".repeat(64);
        var expected = (ObjectNode) JSON.readTree(f.expectedSpec);
        ((ObjectNode) expected.path("containers").get(0)).put("image", declared);
        f.expectedSpec = JSON.writeValueAsString(expected);
        f.bindJobTemplate();
        f.expectedImages = Map.of("runner", actualImageId);
        f.replace("pod", "/spec/containers/0/image", declared);
        f.running();
        f.replace("pod", "/status/containerStatuses/0/imageID", actualImageId);
        assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
        f.replace("pod", "/status/containerStatuses/0/imageID", IMAGE);
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyRunning(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void terminalEvidenceIncludesFinalJobAndEveryRegularInitAndRestartableSidecar() throws Exception {
        var fixture = new Fixture();
        fixture.initialContainers();
        fixture.terminal();
        var evidence = assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyTerminal(fixture.pins(), fixture.namespace, fixture.account, fixture.job, fixture.pod,
                        fixture.runtime));
        assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL, evidence.stage());
        fixture.replace("pod", "/status/initContainerStatuses/1/state", JSON.readTree("{\"running\":{}}"));
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier
                        .verifyTerminal(fixture.pins(), fixture.namespace, fixture.account, fixture.job, fixture.pod,
                                fixture.runtime));
    }

    @Test
    void incompleteRestartedUnknownOrReplacedContainerStatusCannotProveTermination() throws Exception {
        for (String defect : new String[]{"missing", "duplicate", "restart", "image", "container", "unknown", "job"}) {
            var fixture = new Fixture();
            fixture.initialContainers();
            fixture.terminal();
            switch (defect) {
                case "missing" -> fixture.put("pod", "/status", "initContainerStatuses", JSON.readTree("[]"));
                case "duplicate" -> {
                    var root = (ObjectNode) JSON.readTree(fixture.pod);
                    var rows = (com.fasterxml.jackson.databind.node.ArrayNode) root
                            .path("status")
                            .path("initContainerStatuses");
                    rows.set(1, rows.get(0).deepCopy());
                    fixture.pod = JSON.writeValueAsBytes(root);
                }
                case "restart" -> fixture.replace("pod", "/status/initContainerStatuses/1/restartCount", 1);
                case "image" -> fixture.replace("pod", "/status/initContainerStatuses/1/imageID", IMAGE);
                case "container" -> fixture
                        .replace("pod", "/status/containerStatuses/0/state/terminated/containerID",
                                "containerd://different");
                case "unknown" -> fixture
                        .put("pod", "/status/containerStatuses/0/state/terminated", "reason", "ContainerStatusUnknown");
                case "job" -> fixture.put("job", "/status", "conditions", JSON.readTree("[]"));
                default -> throw new AssertionError();
            }
            assertThrows(ObservationFailure.class,
                    () -> KubernetesSnapshotVerifier
                            .verifyTerminal(fixture.pins(), fixture.namespace, fixture.account, fixture.job,
                                    fixture.pod, fixture.runtime),
                    defect);
        }
    }

    @Test
    void perContainerRestartOverridesCannotBeAdoptedAsIrreversibleTerminalEvidence() throws Exception {
        for (String defect : new String[]{"OnFailure", "rules"}) {
            var fixture = new Fixture();
            fixture.initialContainers();
            var spec = (ObjectNode) JSON.readTree(fixture.expectedSpec);
            var initial = (ObjectNode) spec.path("initContainers").get(0);
            if (defect.equals("OnFailure")) {
                initial.put("restartPolicy", "OnFailure");
            } else {
                initial
                        .putArray("restartPolicyRules")
                        .addObject()
                        .put("action", "Restart")
                        .putObject("exitCodes")
                        .put("operator", "In")
                        .putArray("values")
                        .add(1);
            }
            fixture.expectedSpec = JSON.writeValueAsString(spec);
            fixture.bindJobTemplate();
            fixture.put("pod", "", "spec", spec);
            fixture.terminal();
            assertThrows(ObservationFailure.class,
                    () -> KubernetesSnapshotVerifier
                            .verifyTerminal(fixture.pins(), fixture.namespace, fixture.account, fixture.job,
                                    fixture.pod, fixture.runtime),
                    defect);
        }
    }

    @Test
    void terminalEvidenceRejectsIncompleteOrStillActiveRegularContainerStates() throws Exception {
        for (String defect : new String[]{
                "Running",
                "Pending",
                "waiting",
                "multiple-state",
                "missing-id",
                "missing-finish",
                "extra",
                "ephemeral"}) {
            var f = new Fixture();
            f.terminal();
            switch (defect) {
                case "Running", "Pending" -> f.replace("pod", "/status/phase", defect);
                case "waiting" ->
                    f.replace("pod", "/status/containerStatuses/0/state", JSON.readTree("{\"waiting\":{}}"));
                case "multiple-state" ->
                    f.put("pod", "/status/containerStatuses/0/state", "running", JSON.readTree("{}"));
                case "missing-id" -> f.replace("pod", "/status/containerStatuses/0/containerID", null);
                case "missing-finish" ->
                    f.replace("pod", "/status/containerStatuses/0/state/terminated/finishedAt", null);
                case "extra" -> {
                    var pod = (ObjectNode) JSON.readTree(f.pod);
                    var rows = (com.fasterxml.jackson.databind.node.ArrayNode) pod
                            .path("status")
                            .path("containerStatuses");
                    rows.add(((ObjectNode) rows.get(0)).deepCopy().put("name", "unapproved"));
                    f.pod = JSON.writeValueAsBytes(pod);
                }
                case "ephemeral" -> f.put("pod", "/status", "ephemeralContainerStatuses", JSON.readTree("[]"));
                default -> throw new AssertionError();
            }
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyTerminal(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime), defect);
        }
    }

    @Test
    void failedBusinessOutcomeCanStillBeStrictPhysicalTerminationEvidence() throws Exception {
        var f = new Fixture();
        f.terminal();
        f.replace("pod", "/status/phase", "Failed");
        f.replace("pod", "/status/containerStatuses/0/state/terminated/exitCode", 2);
        f.put("job", "/status", "conditions", JSON.readTree("[{\"type\":\"Failed\",\"status\":\"True\"}]"));
        assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL, assertDoesNotThrow(() -> KubernetesSnapshotVerifier
                .verifyTerminal(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime)).stage());
    }

    @Test
    void contradictoryFinalJobConditionsCannotBePresentedAsOneTerminalObservation() throws Exception {
        var f = new Fixture();
        f.terminal();
        f
                .put("job", "/status", "conditions", JSON
                        .readTree(
                                "[{\"type\":\"Complete\",\"status\":\"True\"},{\"type\":\"Failed\",\"status\":\"True\"}]"));
        assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                .verifyTerminal(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void terminalContainerIdentityIsRuntimeQualifiedAndUniqueAcrossRegularInitAndSidecar() throws Exception {
        for (String defect : new String[]{"duplicate", "unqualified"}) {
            var f = new Fixture();
            f.initialContainers();
            f.terminal();
            String id = defect.equals("duplicate") ? "containerd://synthetic-runner" : "copied-container-id";
            f.replace("pod", "/status/initContainerStatuses/1/containerID", id);
            f.replace("pod", "/status/initContainerStatuses/1/state/terminated/containerID", id);
            assertThrows(ObservationFailure.class, () -> KubernetesSnapshotVerifier
                    .verifyTerminal(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime), defect);
        }
    }

    @Test
    void exactStartedRunningPodIsClassifiedWithoutClaimingTerminalEvidence() throws Exception {
        var f = new Fixture();
        f.running();
        f.put("pod", "/status/containerStatuses/0", "containerID", "containerd://synthetic-runner");
        assertEquals("NOT_TERMINAL_YET", progress(f).stage().name());
        var pins = f.pins();
        assertThrows(ObservationFailure.class,
                () -> KubernetesSnapshotVerifier.verifyTerminal(pins, f.namespace, f.account, f.job, f.pod, f.runtime));
    }

    @Test
    void terminalPodWithLaggingJobAndMixedExitingStateRemainWaitableButNeverTerminal() throws Exception {
        var f = new Fixture();
        f.initialContainers();
        f.terminal();
        f.put("job", "/status", "conditions", JSON.readTree("[]"));
        assertEquals("NOT_TERMINAL_YET", progress(f).stage().name());
        f.replace("pod", "/status/phase", "Running");
        f
                .replace("pod", "/status/initContainerStatuses/1/state",
                        JSON.readTree("{\"running\":{\"startedAt\":\"2026-11-06T00:00:00Z\"}}"));
        assertEquals("NOT_TERMINAL_YET", progress(f).stage().name());
        f.terminal();
        assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL, progress(f).stage());
    }

    @Test
    void unknownUnstartedRestartedOrDriftedPodIsNeverAWaitingGrant() throws Exception {
        for (String defect : new String[]{
                "pending",
                "unknown",
                "waiting",
                "not-started",
                "image",
                "restart",
                "missing-id",
                "unqualified-id",
                "uid",
                "spec",
                "deleting",
                "job-terminal-running"}) {
            var f = new Fixture();
            f.running();
            f.put("pod", "/status/containerStatuses/0", "containerID", "containerd://synthetic-runner");
            switch (defect) {
                case "pending" -> f.replace("pod", "/status/phase", "Pending");
                case "unknown" -> f.replace("pod", "/status/phase", "Unknown");
                case "waiting" ->
                    f.replace("pod", "/status/containerStatuses/0/state", JSON.readTree("{\"waiting\":{}}"));
                case "not-started" -> f.replace("pod", "/status/containerStatuses/0/started", false);
                case "image" -> f.replace("pod", "/status/containerStatuses/0/imageID", "sha256:" + "f".repeat(64));
                case "restart" -> f.replace("pod", "/status/containerStatuses/0/restartCount", 1);
                case "missing-id" -> f.replace("pod", "/status/containerStatuses/0/containerID", null);
                case "unqualified-id" -> f.replace("pod", "/status/containerStatuses/0/containerID", "copied-id");
                case "uid" -> f.replace("pod", "/metadata/uid", "799217fb-3fd3-4c01-8319-03792742cd96");
                case "spec" -> f.put("pod", "/spec", "hostPID", true);
                case "deleting" -> f.put("pod", "/metadata", "deletionTimestamp", "2026-11-06T00:00:00Z");
                case "job-terminal-running" -> f
                        .put("job", "/status", "conditions",
                                JSON.readTree("[{\"type\":\"Complete\",\"status\":\"True\"}]"));
                default -> throw new AssertionError(defect);
            }
            assertThrows(ObservationFailure.class, () -> progress(f), defect);
        }
    }

    private static KubernetesSnapshotVerifier.Observation progress(Fixture f) {
        return KubernetesSnapshotVerifier
                .verifyTerminalProgress(f.pins(), f.namespace, f.account, f.job, f.pod, f.runtime);
    }

    private static KubernetesSnapshotVerifier.Pins pins(String namespace, String namespaceUid, String gate, String spec,
            Map<String, String> images) {
        return new KubernetesSnapshotVerifier.Pins(namespace, namespaceUid, "runner", SA_UID, "job-one", JOB_UID,
                "pod-one", POD_UID, "ilm-runsc", "e3496672-0994-4fcb-801f-9018c1fc6f5f", "runsc", gate, spec, JOB_SPEC,
                "{\"handler\":\"runsc\"}", "{\"labels\":{},\"annotations\":{}}", images);
    }

    static final class Fixture {
        byte[] namespace;
        byte[] account;
        byte[] job;
        byte[] pod;
        byte[] runtime;
        private String expectedSpec = SPEC;
        private String expectedJobSpec = JOB_SPEC;
        private String expectedMetadata = "{\"labels\":{},\"annotations\":{}}";
        private Map<String, String> expectedImages = Map.of("runner", IMAGE);

        Fixture() throws Exception {
            namespace = object("v1", "Namespace", "runtime", NS_UID, null, "{}", "{}");
            account = object("v1", "ServiceAccount", "runner", SA_UID, "runtime", "{}", "{}");
            job = object("batch/v1", "Job", "job-one", JOB_UID, "runtime", JOB_SPEC, "{}");
            pod = object("v1", "Pod", "pod-one", POD_UID, "runtime", SPEC, "{\"phase\":\"Pending\"}");
            var p = (ObjectNode) JSON.readTree(pod);
            ((ObjectNode) p.get("metadata")).set("ownerReferences", JSON.readTree("""
                    [{"apiVersion":"batch/v1","kind":"Job","name":"job-one","uid":"%s","controller":true}]
                    """.formatted(JOB_UID)));
            pod = JSON.writeValueAsBytes(p);
            runtime = object("node.k8s.io/v1", "RuntimeClass", "ilm-runsc", "e3496672-0994-4fcb-801f-9018c1fc6f5f",
                    null, "{}", "{}");
            var runtimeObject = (ObjectNode) JSON.readTree(runtime);
            runtimeObject.remove(java.util.Set.of("spec", "status"));
            runtime = JSON.writeValueAsBytes(runtimeObject);
            put("runtime", "", "handler", "runsc");
        }

        KubernetesSnapshotVerifier.Pins pins() {
            return new KubernetesSnapshotVerifier.Pins("runtime", NS_UID, "runner", SA_UID, "job-one", JOB_UID,
                    "pod-one", POD_UID, "ilm-runsc", "e3496672-0994-4fcb-801f-9018c1fc6f5f", "runsc", GATE,
                    expectedSpec, expectedJobSpec, "{\"handler\":\"runsc\"}", expectedMetadata, expectedImages);
        }

        private void initialContainers() throws Exception {
            var s = (ObjectNode) JSON.readTree(expectedSpec);
            s.set("initContainers", JSON.readTree("""
                    [{"name":"directory","image":"sha256:%s"},
                     {"name":"proxy","restartPolicy":"Always","image":"sha256:%s"}]
                    """.formatted("b".repeat(64), "c".repeat(64))));
            expectedSpec = JSON.writeValueAsString(s);
            bindJobTemplate();
            expectedImages = Map
                    .of("runner", IMAGE, "directory", "sha256:" + "b".repeat(64), "proxy", "sha256:" + "c".repeat(64));
            var p = (ObjectNode) JSON.readTree(pod);
            p.set("spec", s);
            pod = JSON.writeValueAsBytes(p);
        }

        private void bindJobTemplate() throws Exception {
            expectedJobSpec = "{\"template\":{\"spec\":" + expectedSpec + "}}";
            put("job", "", "spec", JSON.readTree(expectedJobSpec));
        }

        void running() throws Exception {
            var p = (ObjectNode) JSON.readTree(pod);
            var spec = (ObjectNode) p.get("spec");
            spec.remove("schedulingGates");
            spec.put("nodeName", "node-one");
            p
                    .set("status",
                            JSON
                                    .readTree(
                                            """
                                                    {"phase":"Running","containerStatuses":[{"name":"runner","imageID":"%s",
                                                     "restartCount":0,"started":true,"ready":true,"state":{"running":{"startedAt":"2026-11-06T00:00:00Z"}}}]}
                                                    """
                                                    .formatted(IMAGE)));
            if (expectedImages.size() > 1) {
                ((ObjectNode) p.get("status")).set("initContainerStatuses", JSON.readTree("""
                        [{"name":"directory","restartCount":0,"imageID":"sha256:%s",
                          "state":{"terminated":{"exitCode":0}}},
                         {"name":"proxy","restartCount":0,"imageID":"sha256:%s","started":true,"ready":true,
                          "state":{"running":{"startedAt":"2026-11-06T00:00:00Z"}}}]
                        """.formatted("b".repeat(64), "c".repeat(64))));
            }
            pod = JSON.writeValueAsBytes(p);
        }

        void terminal() throws Exception {
            running();
            var root = (ObjectNode) JSON.readTree(pod);
            var status = (ObjectNode) root.get("status");
            status.put("phase", "Succeeded");
            for (String field : new String[]{"containerStatuses", "initContainerStatuses"}) {
                for (var value : status.path(field)) {
                    var row = (ObjectNode) value;
                    String id = "containerd://synthetic-" + row.path("name").textValue();
                    row.put("containerID", id);
                    row
                            .putObject("state")
                            .putObject("terminated")
                            .put("exitCode", 0)
                            .put("containerID", id)
                            .put("finishedAt", "2026-11-06T00:00:00Z");
                }
            }
            pod = JSON.writeValueAsBytes(root);
            put("job", "/status", "conditions", JSON.readTree("[{\"type\":\"Complete\",\"status\":\"True\"}]"));
        }

        private void replace(String resource, String pointer, Object value) throws Exception {
            int split = pointer.lastIndexOf('/');
            put(resource, pointer.substring(0, split), pointer.substring(split + 1), value);
        }

        private void put(String resource, String parent, String key, Object value) throws Exception {
            var tree = (ObjectNode) JSON.readTree(bytes(resource));
            ((ObjectNode) tree.at(parent)).set(key, JSON.valueToTree(value));
            set(resource, JSON.writeValueAsBytes(tree));
        }

        private byte[] bytes(String resource) {
            return switch (resource) {
                case "namespace" -> namespace;
                case "account" -> account;
                case "job" -> job;
                case "pod" -> pod;
                case "runtime" -> runtime;
                default -> throw new IllegalArgumentException();
            };
        }

        private void set(String resource, byte[] value) {
            switch (resource) {
                case "namespace" -> namespace = value;
                case "account" -> account = value;
                case "job" -> job = value;
                case "pod" -> pod = value;
                case "runtime" -> runtime = value;
                default -> throw new IllegalArgumentException();
            }
        }

        private static byte[] object(String api, String kind, String name, String uid, String namespace, String spec,
                String status) throws Exception {
            var tree = JSON.createObjectNode();
            tree.put("apiVersion", api);
            tree.put("kind", kind);
            var metadata = tree.putObject("metadata");
            metadata.put("name", name);
            metadata.put("uid", uid);
            metadata.put("resourceVersion", kind.equals("Pod") ? "pod-rv-7" : "rv-1");
            if (namespace != null) {
                metadata.put("namespace", namespace);
            }
            tree.set("spec", JSON.readTree(spec));
            tree.set("status", JSON.readTree(status));
            return JSON.writeValueAsBytes(tree);
        }
    }
}
