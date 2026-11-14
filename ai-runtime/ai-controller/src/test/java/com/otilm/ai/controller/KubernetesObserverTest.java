package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Authenticated local API fixtures exercise observation composition, never current deployment authority. */
class KubernetesObserverTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir
    Path directory;

    @Test
    void eligibleObservationComesFromAllSixFixedAuthenticatedResources() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        try (var server = api(objects, list(objects.pod))) {
            var observation = assertDoesNotThrow(() -> KubernetesObserver
                    .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            assertEquals("41093c61-3bc3-427d-8a53-69faea046b58", observation.workload().podUid());
            assertEquals("b97c4892-455d-4708-b843-85c974ed4a30", observation.workload().jobUid());
            assertEquals("pod-rv-7", observation.workload().podResourceVersion());
            assertEquals(KubernetesSnapshotVerifier.Stage.GATED, observation.workload().stage());
            assertEquals(new KubernetesObserver.Versions("rv-1", "rv-1", "rv-1", "list-rv-9", "rv-1"),
                    observation.versions());
            assertEquals(11, server.requests.get());
        }
    }

    @Test
    void runningRequiresAnActualRunningReadAfterTheGateWasReleased() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        objects.running();
        try (var server = api(objects, list(objects.pod))) {
            var observation = assertDoesNotThrow(() -> KubernetesObserver
                    .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.RUNNING));
            assertEquals("node-one", observation.workload().nodeName());
            assertEquals(KubernetesSnapshotVerifier.Stage.RUNNING, observation.workload().stage());
            assertEquals(11, server.requests.get());
        }
    }

    @Test
    void distinctOwnedPodsCanBeObservedByTheirExactPinnedIdentity() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var replacement = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) replacement.get("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
        ((ObjectNode) replacement.get("metadata")).put("name", "replacement");
        try (var server = api(objects, list(objects.pod, JSON.writeValueAsBytes(replacement)))) {
            var observed = assertDoesNotThrow(() -> KubernetesObserver
                    .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            assertEquals(objects.pins().podUid(), observed.workload().podUid());
        }
    }

    @Test
    void duplicateUidOrNameAndMixedJobOwnershipCannotBeSelected() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        for (int defect = 0; defect < 4; defect++) {
            var sibling = (ObjectNode) JSON.readTree(objects.pod);
            var metadata = (ObjectNode) sibling.get("metadata");
            if (defect != 0) {
                metadata.put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
            }
            if (defect != 1) {
                metadata.put("name", "replacement");
            }
            if (defect == 2) {
                ((ObjectNode) metadata.path("ownerReferences").get(0))
                        .put("uid", "cd266a96-068b-4f88-8624-dfdafc375a48");
            } else if (defect == 3) {
                ((com.fasterxml.jackson.databind.node.ArrayNode) metadata.get("ownerReferences"))
                        .add(metadata.path("ownerReferences").get(0).deepCopy());
            }
            try (var server = api(objects, list(objects.pod, JSON.writeValueAsBytes(sibling)))) {
                assertThrows(ObservationFailure.class,
                        observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            }
        }
    }

    @Test
    void missingWrongOrPaginatedListCannotEstablishUniqueOwnership() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var changed = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) changed.get("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
        for (byte[] response : new byte[][]{
                list(),
                list(JSON.writeValueAsBytes(changed)),
                "{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"resourceVersion\":\"r1\",\"continue\":\"next\"},\"items\":[]}"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)}) {
            try (var server = api(objects, response)) {
                assertThrows(ObservationFailure.class,
                        observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            }
        }
    }

    @Test
    void malformedContinuationCannotHideAnotherPageOfOwnedPods() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var response = (ObjectNode) JSON.readTree(list(objects.pod));
        ((ObjectNode) response.get("metadata")).putObject("continue");
        try (var server = api(objects, JSON.writeValueAsBytes(response))) {
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void nonzeroRemainingItemsCannotEstablishSinglePodOwnership() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var response = (ObjectNode) JSON.readTree(list(objects.pod));
        ((ObjectNode) response.get("metadata")).put("remainingItemCount", 1);
        try (var server = api(objects, JSON.writeValueAsBytes(response))) {
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void malformedListIdentityAndOwnerFieldsCannotEstablishOwnership() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        for (String[] mutation : new String[][]{
                {"/apiVersion", "wrong"},
                {"/kind", "wrong"},
                {"/metadata/resourceVersion", ""},
                {"/items/0/apiVersion", "wrong"},
                {"/items/0/kind", "wrong"},
                {"/items/0/metadata/namespace", "different"},
                {"/items/0/metadata/name", "different"},
                {"/items/0/metadata/ownerReferences/0/apiVersion", "wrong"},
                {"/items/0/metadata/ownerReferences/0/kind", "wrong"},
                {"/items/0/metadata/ownerReferences/0/name", "wrong"},
                {"/items/0/metadata/ownerReferences/0/uid", "wrong"}}) {
            var response = (ObjectNode) JSON.readTree(list(objects.pod));
            int slash = mutation[0].lastIndexOf('/');
            ((ObjectNode) response.at(mutation[0].substring(0, slash)))
                    .put(mutation[0].substring(slash + 1), mutation[1]);
            try (var server = api(objects, JSON.writeValueAsBytes(response))) {
                assertThrows(ObservationFailure.class,
                        observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED), mutation[0]);
            }
        }
        var response = (ObjectNode) JSON.readTree(list(objects.pod));
        ((ObjectNode) response.at("/items/0/metadata/ownerReferences/0")).put("controller", false);
        try (var server = api(objects, JSON.writeValueAsBytes(response))) {
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void listAndNameLookupMustReferToTheSamePodResourceVersion() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        byte[] listed = list(objects.pod);
        var changed = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) changed.get("metadata")).put("resourceVersion", "pod-rv-8");
        objects.pod = JSON.writeValueAsBytes(changed);
        try (var server = api(objects, listed)) {
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void jobChangedDuringTheObservationCannotBecomeEligible() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var changed = (ObjectNode) JSON.readTree(objects.job);
        ((ObjectNode) changed.get("metadata")).put("resourceVersion", "job-rv-2");
        ((ObjectNode) changed.get("spec")).put("parallelism", 2);
        try (var server = api(objects, list(objects.pod))) {
            server.secondRoutes = Map
                    .of("/apis/batch/v1/namespaces/runtime/jobs/job-one", JSON.writeValueAsBytes(changed));
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void aSecondOwnedPodAppearingDuringTheObservationCannotBeIgnored() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var replacement = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) replacement.get("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
        ((ObjectNode) replacement.get("metadata")).put("name", "replacement");
        try (var server = api(objects, list(objects.pod))) {
            server.secondRoutes = Map
                    .of("/api/v1/namespaces/runtime/pods", list(objects.pod, JSON.writeValueAsBytes(replacement)));
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
        }
    }

    @Test
    void rawApiListItemsMayOmitTheirTypeMetadata() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var response = (ObjectNode) JSON.readTree(list(objects.pod));
        ((ObjectNode) response.path("items").get(0)).remove(java.util.Set.of("apiVersion", "kind"));
        try (var server = api(objects, JSON.writeValueAsBytes(response))) {
            var evidence = assertDoesNotThrow(() -> KubernetesObserver
                    .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            assertEquals("41093c61-3bc3-427d-8a53-69faea046b58", evidence.workload().podUid());
        }
    }

    @Test
    void aNewCollectionRevisionWithIdenticalItemsIsNotWorkloadDrift() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var changed = (ObjectNode) JSON.readTree(list(objects.pod));
        ((ObjectNode) changed.get("metadata")).put("resourceVersion", "collection-rv-10");
        try (var server = api(objects, list(objects.pod))) {
            server.secondRoutes = Map.of("/api/v1/namespaces/runtime/pods", JSON.writeValueAsBytes(changed));
            var evidence = assertDoesNotThrow(() -> KubernetesObserver
                    .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            assertEquals("list-rv-9", evidence.versions().podList());
        }
    }

    @Test
    void anOwnedPodChangingInTheFinalListReadCannotUseTheEarlierGet() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        var changed = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) changed.get("metadata")).put("resourceVersion", "pod-rv-8");
        try (var server = api(objects, list(objects.pod))) {
            server.secondRoutes = Map.of("/api/v1/namespaces/runtime/pods", list(JSON.writeValueAsBytes(changed)));
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.GATED));
            assertEquals(11, server.requests.get());
        }
    }

    @Test
    void terminalUsesAllElevenAuthenticatedReadsAndRejectsFinalReplacementOrExtraOwnedPods() throws Exception {
        for (String defect : new String[]{"none", "replacement", "extra", "resource-version"}) {
            var objects = new KubernetesSnapshotVerifierTest.Fixture();
            objects.terminal();
            try (var server = api(objects, list(objects.pod))) {
                if (!defect.equals("none")) {
                    var changed = (ObjectNode) JSON.readTree(objects.pod);
                    ((ObjectNode) changed.get("metadata"))
                            .put(defect.equals("resource-version") ? "resourceVersion" : "uid",
                                    defect.equals("resource-version")
                                            ? "new-rv"
                                            : "799217fb-3fd3-4c01-8319-03792742cd96");
                    server.secondRoutes = Map
                            .of("/api/v1/namespaces/runtime/pods",
                                    defect.equals("extra")
                                            ? list(objects.pod, JSON.writeValueAsBytes(changed))
                                            : list(JSON.writeValueAsBytes(changed)));
                    assertThrows(ObservationFailure.class,
                            observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.TERMINAL));
                } else {
                    var evidence = assertDoesNotThrow(() -> KubernetesObserver
                            .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.TERMINAL));
                    assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL, evidence.workload().stage());
                    assertEquals("41093c61-3bc3-427d-8a53-69faea046b58", evidence.workload().podUid());
                }
                assertEquals(11, server.requests.get());
                assertEquals("Bearer synthetic.api.token", server.authorization.get());
            }
        }
    }

    @Test
    void aWaitingClassificationStillRequiresEveryStableIdentityAndCompleteSecondListRead() throws Exception {
        for (String defect : new String[]{"none", "replacement", "resource-version", "extra"}) {
            var objects = new KubernetesSnapshotVerifierTest.Fixture();
            objects.running();
            var pod = (ObjectNode) JSON.readTree(objects.pod);
            ((ObjectNode) pod.at("/status/containerStatuses/0")).put("containerID", "containerd://synthetic-runner");
            objects.pod = JSON.writeValueAsBytes(pod);
            try (var server = api(objects, list(objects.pod))) {
                if (!defect.equals("none")) {
                    var changed = pod.deepCopy();
                    ((ObjectNode) changed.get("metadata"))
                            .put(defect.equals("resource-version") ? "resourceVersion" : "uid",
                                    defect.equals("resource-version")
                                            ? "new-rv"
                                            : "799217fb-3fd3-4c01-8319-03792742cd96");
                    server.secondRoutes = Map
                            .of("/api/v1/namespaces/runtime/pods",
                                    defect.equals("extra")
                                            ? list(objects.pod, JSON.writeValueAsBytes(changed))
                                            : list(JSON.writeValueAsBytes(changed)));
                    if (defect.equals("resource-version")) {
                        assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET,
                                KubernetesObserver
                                        .observe(client(server), objects.pins(),
                                                KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET)
                                        .workload()
                                        .stage());
                    } else {
                        assertThrows(ObservationFailure.class,
                                observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET));
                    }
                } else {
                    var result = KubernetesObserver
                            .observe(client(server), objects.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
                    assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET, result.workload().stage());
                }
                assertEquals(defect.equals("resource-version") ? 12 : 11, server.requests.get());
            }
        }
    }

    @Test
    void independentlyValidTerminationOnTheRereadCannotGrantTerminalCreditUntilAStablePoll() throws Exception {
        var first = startedObjects();
        var second = new KubernetesSnapshotVerifierTest.Fixture();
        second.terminal();
        try (var server = api(first, list(first.pod))) {
            server.secondRoutes = Map
                    .of("/apis/batch/v1/namespaces/runtime/jobs/job-one", second.job, "/api/v1/namespaces/runtime/pods",
                            list(second.pod), "/api/v1/namespaces/runtime/pods/pod-one", second.pod);
            var progress = KubernetesObserver
                    .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
            assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET, progress.workload().stage());
            assertEquals(12, server.requests.get());
            var stable = KubernetesObserver
                    .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
            assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL, stable.workload().stage());
        }
    }

    @Test
    void resourceVersionAndTrackingFinalizerProgressMayOnlyRemainNotYetTerminal() throws Exception {
        var first = startedObjects();
        var original = (ObjectNode) JSON.readTree(first.pod);
        ((ObjectNode) original.path("metadata")).putArray("finalizers").add("batch.kubernetes.io/job-tracking");
        first.pod = JSON.writeValueAsBytes(original);
        var second = startedObjects();
        var pod = (ObjectNode) JSON.readTree(second.pod);
        ((ObjectNode) pod.path("metadata")).put("resourceVersion", "next-rv").putArray("finalizers");
        second.pod = JSON.writeValueAsBytes(pod);
        var job = (ObjectNode) JSON.readTree(second.job);
        ((ObjectNode) job.path("metadata")).put("resourceVersion", "next-job-rv");
        second.job = JSON.writeValueAsBytes(job);
        try (var server = api(first, list(first.pod))) {
            server.secondRoutes = Map
                    .of("/apis/batch/v1/namespaces/runtime/jobs/job-one", second.job, "/api/v1/namespaces/runtime/pods",
                            list(second.pod), "/api/v1/namespaces/runtime/pods/pod-one", second.pod);
            var progress = KubernetesObserver
                    .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
            assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET, progress.workload().stage());
            assertEquals("next-rv", progress.workload().podResourceVersion());
        }
    }

    @Test
    void aChangedSecondSnapshotMustIndependentlyPassTheSameExactFootprintAndProfileChecks() throws Exception {
        for (String defect : new String[]{
                "job-uid",
                "job-spec",
                "pod-uid",
                "pod-spec",
                "image",
                "unknown-state",
                "extra-owned",
                "get-uid-disagrees",
                "namespace",
                "malformed"}) {
            var first = startedObjects();
            var second = new KubernetesSnapshotVerifierTest.Fixture();
            second.terminal();
            var pod = (ObjectNode) JSON.readTree(second.pod);
            var job = (ObjectNode) JSON.readTree(second.job);
            switch (defect) {
                case "job-uid" ->
                    ((ObjectNode) job.path("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
                case "job-spec" -> ((ObjectNode) job.path("spec")).put("backoffLimit", 1);
                case "pod-uid" ->
                    ((ObjectNode) pod.path("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
                case "pod-spec" -> ((ObjectNode) pod.path("spec")).put("hostPID", true);
                case "image" ->
                    ((ObjectNode) pod.at("/status/containerStatuses/0")).put("imageID", "sha256:" + "f".repeat(64));
                case "unknown-state" -> ((ObjectNode) pod.at("/status/containerStatuses/0/state/terminated"))
                        .put("reason", "ContainerStatusUnknown");
                default -> {
                }
            }
            byte[] changedPod = JSON.writeValueAsBytes(pod);
            var routes = new java.util.HashMap<String, byte[]>();
            routes.put("/apis/batch/v1/namespaces/runtime/jobs/job-one", JSON.writeValueAsBytes(job));
            routes
                    .put("/api/v1/namespaces/runtime/pods",
                            defect.equals("malformed")
                                    ? new byte[]{'{'}
                                    : defect.equals("extra-owned") ? list(first.pod, changedPod) : list(changedPod));
            var changedGet = (ObjectNode) JSON.readTree(changedPod);
            if (defect.equals("get-uid-disagrees")) {
                ((ObjectNode) changedGet.path("metadata")).put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
            }
            routes.put("/api/v1/namespaces/runtime/pods/pod-one", JSON.writeValueAsBytes(changedGet));
            if (defect.equals("namespace")) {
                var namespace = (ObjectNode) JSON.readTree(first.namespace);
                ((ObjectNode) namespace.path("metadata")).put("resourceVersion", "changed-authority");
                routes.put("/api/v1/namespaces/runtime", JSON.writeValueAsBytes(namespace));
            }
            try (var server = api(first, list(first.pod))) {
                server.secondRoutes = Map.copyOf(routes);
                assertThrows(ObservationFailure.class,
                        observation(server, first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET), defect);
            }
        }
    }

    @Test
    void aLateOwnedSiblingCannotBorrowTheSelectedPodsTerminalProgressProof() throws Exception {
        var objects = startedObjects();
        var sibling = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) sibling.path("metadata"))
                .put("name", "late-sibling")
                .put("uid", "799217fb-3fd3-4c01-8319-03792742cd96");
        try (var server = api(objects, list(objects.pod))) {
            var later = new java.util.HashMap<>(progressRoutes(objects.job, objects.pod, objects.pod));
            later.put("/api/v1/namespaces/runtime/pods", list(objects.pod, JSON.writeValueAsBytes(sibling)));
            server.secondRoutes = Map.copyOf(later);
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET));
        }
    }

    @Test
    void validProgressBetweenTheFirstListAndGetNeverGrantsTerminalCredit() throws Exception {
        var first = startedObjects();
        var second = new KubernetesSnapshotVerifierTest.Fixture();
        second.terminal();
        var listed = (ObjectNode) JSON.readTree(first.pod);
        listed.remove(java.util.Set.of("apiVersion", "kind"));
        try (var server = api(first, list(JSON.writeValueAsBytes(listed)))) {
            var initial = new java.util.HashMap<>(server.routes);
            initial.put("/api/v1/namespaces/runtime/pods/pod-one", second.pod);
            server.routes = Map.copyOf(initial);
            server.secondRoutes = progressRoutes(second.job, second.pod, second.pod);
            var observation = KubernetesObserver
                    .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
            assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET, observation.workload().stage());
            assertEquals(12, server.requests.get());
            assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL,
                    KubernetesObserver
                            .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET)
                            .workload()
                            .stage());
        }
    }

    @Test
    void validProgressBetweenTheSecondListAndGetNeverGrantsTerminalCredit() throws Exception {
        var first = startedObjects();
        var listed = (ObjectNode) JSON.readTree(first.pod);
        ((ObjectNode) listed.path("metadata")).put("resourceVersion", "second-list-rv");
        var second = new KubernetesSnapshotVerifierTest.Fixture();
        second.terminal();
        try (var server = api(first, list(first.pod))) {
            server.secondRoutes = progressRoutes(first.job, JSON.writeValueAsBytes(listed), second.pod);
            assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET,
                    KubernetesObserver
                            .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET)
                            .workload()
                            .stage());
            server.secondRoutes = progressRoutes(second.job, second.pod, second.pod);
            assertEquals(KubernetesSnapshotVerifier.Stage.TERMINAL,
                    KubernetesObserver
                            .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET)
                            .workload()
                            .stage());
        }
    }

    @Test
    void bookkeepingCannotMaskAProfileOrPhysicalContainerIdentityChange() throws Exception {
        for (String defect : new String[]{
                "none",
                "spec",
                "container-id",
                "creation-time",
                "unknown-finalizer",
                "malformed-bookkeeping"}) {
            var first = startedObjects();
            var pod = (ObjectNode) JSON.readTree(first.pod);
            ((ObjectNode) pod.path("metadata"))
                    .putArray("managedFields")
                    .addObject()
                    .put("manager", "synthetic-status-writer");
            switch (defect) {
                case "spec" -> ((ObjectNode) pod.path("spec")).put("hostPID", true);
                case "container-id" ->
                    ((ObjectNode) pod.at("/status/containerStatuses/0")).put("containerID", "containerd://replacement");
                case "creation-time" ->
                    ((ObjectNode) pod.path("metadata")).put("creationTimestamp", "2026-11-06T00:00:01Z");
                case "unknown-finalizer" ->
                    ((ObjectNode) pod.path("metadata")).putArray("finalizers").add("other.invalid/hold");
                case "malformed-bookkeeping" ->
                    ((ObjectNode) pod.path("metadata")).put("managedFields", "not-an-array");
                default -> {
                }
            }
            byte[] current = JSON.writeValueAsBytes(pod);
            try (var server = api(first, list(first.pod))) {
                server.secondRoutes = progressRoutes(first.job, current, current);
                if (defect.equals("none")) {
                    assertEquals(KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET, KubernetesObserver
                            .observe(client(server), first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET)
                            .workload()
                            .stage());
                } else {
                    assertThrows(ObservationFailure.class,
                            observation(server, first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET),
                            defect);
                }
            }
        }
    }

    @Test
    void aFirstListVersionWithSecurityDriftCannotUseAValidGetAsItsReplacement() throws Exception {
        var objects = startedObjects();
        var listed = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) listed.path("spec")).put("hostPID", true);
        try (var server = api(objects, list(JSON.writeValueAsBytes(listed)))) {
            assertThrows(ObservationFailure.class,
                    observation(server, objects.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET));
        }
    }

    @Test
    void firstListGetProgressRemainsAHardFailureInStrictRunningAndTerminalStages() throws Exception {
        for (var stage : new KubernetesSnapshotVerifier.Stage[]{
                KubernetesSnapshotVerifier.Stage.RUNNING,
                KubernetesSnapshotVerifier.Stage.TERMINAL}) {
            var objects = stage == KubernetesSnapshotVerifier.Stage.RUNNING
                    ? startedObjects()
                    : new KubernetesSnapshotVerifierTest.Fixture();
            if (stage == KubernetesSnapshotVerifier.Stage.TERMINAL) {
                objects.terminal();
            }
            var changed = (ObjectNode) JSON.readTree(objects.pod);
            ((ObjectNode) changed.path("metadata")).put("resourceVersion", "next-get-rv");
            try (var server = api(objects, list(objects.pod))) {
                var routes = new java.util.HashMap<>(server.routes);
                routes.put("/api/v1/namespaces/runtime/pods/pod-one", JSON.writeValueAsBytes(changed));
                server.routes = Map.copyOf(routes);
                assertThrows(ObservationFailure.class,
                        () -> KubernetesObserver.observe(client(server), objects.pins(), stage));
            }
        }
    }

    @Test
    void malformedNonAuthorizingBookkeepingCannotBeNormalizedIntoValidProgress() throws Exception {
        for (String invalid : new String[]{
                "{\"managedFields\":\"invalid\"}",
                "{\"managedFields\":[null]}",
                "{\"finalizers\":\"invalid\"}",
                "{\"finalizers\":[1]}",
                "{\"finalizers\":[\" \"]}",
                "{\"finalizers\":[\"batch.kubernetes.io/job-tracking\",\"batch.kubernetes.io/job-tracking\"]}"}) {
            var first = startedObjects();
            var changed = (ObjectNode) JSON.readTree(first.pod);
            ((ObjectNode) changed.path("metadata")).setAll((ObjectNode) JSON.readTree(invalid));
            byte[] current = JSON.writeValueAsBytes(changed);
            try (var server = api(first, list(first.pod))) {
                server.secondRoutes = progressRoutes(first.job, current, current);
                assertThrows(ObservationFailure.class,
                        observation(server, first.pins(), KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET), invalid);
            }
        }
    }

    private static Map<String, byte[]> progressRoutes(byte[] job, byte[] listed, byte[] get) throws Exception {
        return Map
                .of("/apis/batch/v1/namespaces/runtime/jobs/job-one", job, "/api/v1/namespaces/runtime/pods",
                        list(listed), "/api/v1/namespaces/runtime/pods/pod-one", get);
    }

    private static KubernetesSnapshotVerifierTest.Fixture startedObjects() throws Exception {
        var objects = new KubernetesSnapshotVerifierTest.Fixture();
        objects.running();
        var pod = (ObjectNode) JSON.readTree(objects.pod);
        ((ObjectNode) pod.at("/status/containerStatuses/0")).put("containerID", "containerd://synthetic-runner");
        objects.pod = JSON.writeValueAsBytes(pod);
        return objects;
    }

    private org.junit.jupiter.api.function.Executable observation(KubernetesHttpsFixture server,
            KubernetesSnapshotVerifier.Pins pins, KubernetesSnapshotVerifier.Stage stage) throws Exception {
        var api = client(server);
        return () -> KubernetesObserver.observe(api, pins, stage);
    }

    private KubernetesApi client(KubernetesHttpsFixture server) throws Exception {
        Path token = Files.createTempFile(directory, "controller-", ".token");
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        Files.writeString(token, "synthetic.api.token");
        return new KubernetesApi(server.endpoint(), server.trust(), token, Duration.ofSeconds(5));
    }

    private static KubernetesHttpsFixture api(KubernetesSnapshotVerifierTest.Fixture o, byte[] list) throws Exception {
        var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
        server.routes = Map
                .of("/api/v1/namespaces/runtime", o.namespace, "/api/v1/namespaces/runtime/serviceaccounts/runner",
                        o.account, "/apis/batch/v1/namespaces/runtime/jobs/job-one", o.job,
                        "/api/v1/namespaces/runtime/pods", list, "/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc",
                        o.runtime, "/api/v1/namespaces/runtime/pods/pod-one", o.pod);
        return server;
    }

    private static byte[] list(byte[]... pods) throws Exception {
        var root = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
        root.putObject("metadata").put("resourceVersion", "list-rv-9");
        var items = root.putArray("items");
        for (byte[] pod : pods) {
            items.add(JSON.readTree(pod));
        }
        return JSON.writeValueAsBytes(root);
    }
}
