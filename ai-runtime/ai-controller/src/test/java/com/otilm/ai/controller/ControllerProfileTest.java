package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Synthetic administrator recipes test canonical binding, never deployed profile or launch authority. */
class ControllerProfileTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID ATTEMPT = UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99");
    private static final String JOB = "ilm-ai-d00f5707e1ad41e09f21b66c74358c99";
    private static final String SPEC = """
            {"serviceAccountName":"runner","runtimeClassName":"ilm-runsc","restartPolicy":"Never",
             "automountServiceAccountToken":false,"activeDeadlineSeconds":27,"terminationGracePeriodSeconds":1,"schedulingGates":[{"name":"ilm.otilm.ai/runtime-eligible"}],
             "containers":[{"name":"runner","image":"local.invalid/runner@sha256:%s",
               "command":["/opt/java/openjdk/bin/java","com.otilm.ai.runner.RunnerBootstrapMain"],
               "securityContext":{"runAsUser":65532,"runAsGroup":65532,"allowPrivilegeEscalation":false}}]}
            """
            .formatted("a".repeat(64));
    static final String PROFILE = """
            {"version":1,"pins":{"cluster":"lab","namespaceName":"runtime",
              "namespaceUid":"77bd9027-9e2a-43b4-890f-a36eb970ae46","serviceAccountName":"runner",
              "serviceAccountUid":"f520b467-e75e-4b51-9579-d9af91d683aa","runtimeClass":"ilm-runsc",
              "imageDigest":"sha256:%s","templateDigest":"sha256:%s","profileRevision":11,
              "securityRevision":12,"trustRevision":13,"protocol":"v1"},
             "runtime":{"uid":"bb92d9d9-796b-427e-9e29-daa69c8a061b","handler":"runsc",
               "schedulingGate":"ilm.otilm.ai/runtime-eligible","configuration":{"handler":"runsc"}},
             "job":{"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"runtime","name":"%s"},
               "spec":{"parallelism":1,"completions":1,"backoffLimit":0,"manualSelector":true,
                 "selector":{"matchLabels":{"ilm.otilm.ai/attempt":"%s"}},
                 "template":{"metadata":{"labels":{"ilm.otilm.ai/attempt":"%s"}},"spec":%s}}},
             "podSpec":%s,"podMetadata":{"labels":{"ilm.otilm.ai/attempt":"%s"},"annotations":{}},
             "imageIds":{"runner":"containerd://sha256:%s"}}
            """.formatted("a".repeat(64), "b".repeat(64), JOB, ATTEMPT, ATTEMPT, SPEC, SPEC, ATTEMPT, "c".repeat(64));
    @TempDir
    Path directory;

    @Test
    void acceptedLiteralRecipeMatchesAllCanonicalLaunchPinsBeforeProducingCreationBytes() throws Exception {
        var profile = assertDoesNotThrow(() -> ControllerProfile.read(file(PROFILE)));
        assertDoesNotThrow(() -> profile.requireLaunch(launch("sha256:" + "a".repeat(64), 11, "runtime")));
        var job = JSON.readTree(profile.job());
        assertEquals("batch/v1", job.path("apiVersion").textValue());
        assertEquals(JOB, job.path("metadata").path("name").textValue());
        assertEquals(JSON.readTree(SPEC), job.path("spec").path("template").path("spec"));
        var pins = profile
                .pins("736947e7-2778-4b40-8b0b-a514e319113c", "actual-pod-one", "34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3");
        assertEquals("736947e7-2778-4b40-8b0b-a514e319113c", pins.jobUid());
        assertEquals("actual-pod-one", pins.podName());
        assertEquals("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3", pins.podUid());
        assertEquals("containerd://sha256:" + "c".repeat(64), pins.imageIds().get("runner"));
        assertEquals(JSON.readTree(SPEC), JSON.readTree(pins.podSpecJson()));
        assertEquals(job.path("spec"), JSON.readTree(pins.jobSpecJson()));
    }

    @Test
    void runnerProfileRequiresTheApprovedNativeBudgetWithoutACompetingJobDeadline() throws Exception {
        var good = (ObjectNode) JSON.readTree(PROFILE);
        for (String pointer : List.of("/podSpec", "/job/spec/template/spec")) {
            ((ObjectNode) good.at(pointer)).put("activeDeadlineSeconds", 27).put("terminationGracePeriodSeconds", 1);
        }
        assertDoesNotThrow(() -> ControllerProfile.read(file(good.toString())).requireRunnerDeadline());
        for (Object deadline : new Object[]{26, 28, 30, 180, 27.0, "27", false}) {
            var bad = good.deepCopy();
            for (String pointer : List.of("/podSpec", "/job/spec/template/spec")) {
                ((ObjectNode) bad.at(pointer)).set("activeDeadlineSeconds", JSON.valueToTree(deadline));
            }
            var profile = ControllerProfile.read(file(bad.toString()));
            assertThrows(ObservationFailure.class, profile::requireRunnerDeadline);
        }
        for (String field : List.of("activeDeadlineSeconds", "terminationGracePeriodSeconds")) {
            var bad = good.deepCopy();
            for (String pointer : List.of("/podSpec", "/job/spec/template/spec")) {
                ((ObjectNode) bad.at(pointer)).remove(field);
            }
            var profile = ControllerProfile.read(file(bad.toString()));
            assertThrows(ObservationFailure.class, profile::requireRunnerDeadline);
        }
        for (String field : List.of("terminationGracePeriodSeconds", "restartPolicy")) {
            var bad = good.deepCopy();
            for (String pointer : List.of("/podSpec", "/job/spec/template/spec")) {
                ((ObjectNode) bad.at(pointer))
                        .set(field,
                                field.equals("restartPolicy") ? JSON.valueToTree("OnFailure") : JSON.valueToTree(2));
            }
            var profile = ControllerProfile.read(file(bad.toString()));
            assertThrows(ObservationFailure.class, profile::requireRunnerDeadline);
        }
        for (String field : List.of("activeDeadlineSeconds", "ttlSecondsAfterFinished")) {
            var bad = good.deepCopy();
            ((ObjectNode) bad.at("/job/spec")).put(field, 27);
            var profile = ControllerProfile.read(file(bad.toString()));
            assertThrows(ObservationFailure.class, profile::requireRunnerDeadline);
        }
    }

    @Test
    void runnerJobsMustDeclareIntegralZeroRetriesInsteadOfTheKubernetesDefault() throws Exception {
        for (Object value : new Object[]{null, 1, -1, 0.0, "0", false}) {
            var recipe = (ObjectNode) JSON.readTree(PROFILE);
            var jobSpec = (ObjectNode) recipe.path("job").path("spec");
            if (value == null) {
                jobSpec.remove("backoffLimit");
            } else {
                jobSpec.set("backoffLimit", JSON.valueToTree(value));
            }
            var profile = ControllerProfile.read(file(recipe.toString()));
            assertThrows(ObservationFailure.class, profile::requireRunnerDeadline);
        }
    }

    @Test
    void aCoreReplyForOtherPinsCannotSelectThisAdministratorRecipe() throws Exception {
        var profile = assertDoesNotThrow(() -> ControllerProfile.read(file(PROFILE)));
        for (var binding : new ControllerWire.Launch[]{
                launch("sha256:" + "d".repeat(64), 11, "runtime"),
                launch("sha256:" + "a".repeat(64), 14, "runtime"),
                launch("sha256:" + "a".repeat(64), 11, "other")}) {
            assertThrows(ObservationFailure.class, () -> profile.requireLaunch(binding));
        }
        assertThrows(ObservationFailure.class, () -> profile.requireLaunch(null));
    }

    @Test
    void unknownDuplicateUnboundedAndUnlinkedRecipesFailBeforeAnyApiUse() throws Exception {
        for (String invalid : new String[]{
                PROFILE + "{}",
                PROFILE.replace("\"version\":1", "\"version\":1,\"version\":1"),
                PROFILE.replace("\"version\":1", "\"version\":1,\"ready\":true"),
                PROFILE.replace("\"profileRevision\":11", "\"profileRevision\":4294967297.0"),
                PROFILE.replaceFirst("\"handler\":\"runsc\"", "\"handler\":\"runc\""),
                PROFILE.replace("\"namespace\":\"runtime\"", "\"namespace\":\"other\""),
                PROFILE.replace("\"kind\":\"Job\"", "\"kind\":\"Pod\""),
                PROFILE.replaceFirst("\"serviceAccountName\":\"runner\"", "\"serviceAccountName\":\"other\""),
                " ".repeat(1_048_577)}) {
            Path path = file(invalid);
            assertThrows(ObservationFailure.class, () -> ControllerProfile.read(path));
        }
        Path path = file(PROFILE);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw-rw-"));
        assertThrows(ObservationFailure.class, () -> ControllerProfile.read(path));
    }

    @Test
    void everyCanonicalCorePinIsComparedBeforeLiteralJobCreation() throws Exception {
        var profile = ControllerProfile.read(file(PROFILE));
        var good = launch("sha256:" + "a".repeat(64), 11, "runtime");
        for (var defect : Map
                .ofEntries(Map.entry("cluster", "other"), Map.entry("namespaceName", "other"),
                        Map.entry("namespaceUid", UUID.randomUUID().toString()),
                        Map.entry("serviceAccountName", "other"),
                        Map.entry("serviceAccountUid", UUID.randomUUID().toString()),
                        Map.entry("runtimeClass", "other"), Map.entry("imageDigest", "sha256:" + "d".repeat(64)),
                        Map.entry("templateDigest", "sha256:" + "e".repeat(64)), Map.entry("profileRevision", 14),
                        Map.entry("securityRevision", 15), Map.entry("trustRevision", 16))
                .entrySet()) {
            var body = (ObjectNode) JSON.readTree(ControllerWire.launchReply(good));
            body.set(defect.getKey(), JSON.valueToTree(defect.getValue()));
            var changed = ControllerWire.readLaunchReply(JSON.writeValueAsBytes(body), good.locator());
            assertThrows(ObservationFailure.class, () -> profile.requireLaunch(changed), defect.getKey());
        }
        var body = (ObjectNode) JSON.readTree(ControllerWire.launchReply(good));
        var otherAttempt = UUID.randomUUID();
        body
                .put("attemptId", otherAttempt.toString())
                .put("jobName", "ilm-ai-" + otherAttempt.toString().replace("-", ""));
        var changed = ControllerWire
                .readLaunchReply(JSON.writeValueAsBytes(body), new ControllerWire.Locator(
                        good.locator().correlationId(), good.locator().runId(), otherAttempt));
        assertThrows(ObservationFailure.class, () -> profile.requireLaunch(changed));
    }

    @Test
    void closedRecipeRejectsAmbiguousGatesMetadataAndContainerIdentityMaps() throws Exception {
        for (var defect : List
                .of(Map.entry("/version", "0"), Map.entry("/runtime/configuration", "[]"),
                        Map.entry("/runtime/schedulingGate", "\"invalid-gate\""),
                        Map.entry("/job/apiVersion", "\"v1\""), Map.entry("/job/metadata/uid", "\"copied-uid\""),
                        Map.entry("/podSpec/schedulingGates", "[]"),
                        Map
                                .entry("/podSpec/schedulingGates",
                                        "[{\"name\":\"ilm.otilm.ai/runtime-eligible\",\"extra\":true}]"),
                        Map.entry("/podSpec/nodeName", "\"caller-selected-node\""),
                        Map.entry("/podMetadata/labels", "[]"), Map.entry("/imageIds", "{}"),
                        Map.entry("/imageIds/runner", "\"copied-image-label\""),
                        Map.entry("/imageIds/extra", "\"sha256:" + "d".repeat(64) + "\""),
                        Map.entry("/podSpec/containers", "[]"),
                        Map.entry("/podSpec/initContainers", "[{\"name\":\"runner\"}]"))) {
            var root = (ObjectNode) JSON.readTree(PROFILE);
            int separator = defect.getKey().lastIndexOf('/');
            ((ObjectNode) root.at(defect.getKey().substring(0, separator)))
                    .set(defect.getKey().substring(separator + 1), JSON.readTree(defect.getValue()));
            if (defect.getKey().startsWith("/podSpec/")) {
                ((ObjectNode) root.path("job").path("spec").path("template"))
                        .set("spec", root.path("podSpec").deepCopy());
            }
            var path = file(JSON.writeValueAsString(root));
            assertThrows(ObservationFailure.class, () -> ControllerProfile.read(path), defect.getKey());
        }
    }

    @Test
    void discoveryRequiresACompleteNamespaceListAndTheUniqueActualControllingJobUid() throws Exception {
        var profile = ControllerProfile.read(file(PROFILE));
        var root = JSON.createObjectNode().put("apiVersion", "v1").put("kind", "PodList");
        root.putObject("metadata").put("resourceVersion", "current-list-rv");
        var pod = root.putArray("items").addObject().put("apiVersion", "v1").put("kind", "Pod");
        var metadata = pod
                .putObject("metadata")
                .put("namespace", "runtime")
                .put("name", "actual-one")
                .put("uid", "34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3");
        metadata
                .putArray("ownerReferences")
                .addObject()
                .put("apiVersion", "batch/v1")
                .put("kind", "Job")
                .put("name", JOB)
                .put("uid", "736947e7-2778-4b40-8b0b-a514e319113c")
                .put("controller", true);
        String job = "736947e7-2778-4b40-8b0b-a514e319113c";
        assertEquals("actual-one", profile.findPod(JSON.writeValueAsBytes(root), job).orElseThrow().podName());
        for (var defect : List
                .of(Map.entry("/metadata/continue", "\"next-shard\""), Map.entry("/metadata/remainingItemCount", "1"),
                        Map.entry("/metadata/remainingItemCount", "\"0\""),
                        Map.entry("/items/0/metadata/namespace", "\"other\""),
                        Map
                                .entry("/items/0/metadata/ownerReferences/0/uid",
                                        "\"4a196bbd-5bd3-49ce-9223-f334c16239a1\""),
                        Map.entry("/items/0/metadata/ownerReferences/0/controller", "false"),
                        Map.entry("/items/0/metadata/ownerReferences/0/apiVersion", "\"v1\""))) {
            var invalid = root.deepCopy();
            int separator = defect.getKey().lastIndexOf('/');
            ((ObjectNode) invalid.at(defect.getKey().substring(0, separator)))
                    .set(defect.getKey().substring(separator + 1), JSON.readTree(defect.getValue()));
            assertThrows(ObservationFailure.class, () -> profile.findPod(JSON.writeValueAsBytes(invalid), job),
                    defect.getKey());
        }
        var duplicated = root.deepCopy();
        ((com.fasterxml.jackson.databind.node.ArrayNode) duplicated.get("items")).add(pod.deepCopy());
        assertThrows(ObservationFailure.class, () -> profile.findPod(JSON.writeValueAsBytes(duplicated), job));
        var empty = root.deepCopy();
        empty.putArray("items");
        assertEquals(java.util.Optional.empty(), profile.findPod(JSON.writeValueAsBytes(empty), job));
    }

    private static ControllerWire.Launch launch(String image, long profileRevision, String namespace) {
        var locator = new ControllerWire.Locator(UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
                UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"), ATTEMPT);
        return new ControllerWire.Launch(locator, 7, 3, Instant.parse("2026-11-06T18:00:30Z"),
                Instant.parse("2026-11-06T18:01:30Z"), image, profileRevision, 12, 13, "v1", "lab", namespace,
                UUID.fromString("77bd9027-9e2a-43b4-890f-a36eb970ae46"), "runner",
                UUID.fromString("f520b467-e75e-4b51-9579-d9af91d683aa"), "sha256:" + "b".repeat(64), "ilm-runsc", JOB);
    }

    private Path file(String value) throws Exception {
        Path path = Files.createTempFile(directory, "profile-", ".json");
        Files.writeString(path, value, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        return path;
    }
}
