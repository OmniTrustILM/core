package com.otilm.ai.controller;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** An API identity/profile observation grants no readiness, workload registration or business authority. */
public final class KubernetesSnapshotVerifier {
    private static final int MAXIMUM = 1_048_576;
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory
            .builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints
                    .builder()
                    .maxNestingDepth(64)
                    .maxNameLength(512)
                    .maxStringLength(65_536)
                    .maxNumberLength(64)
                    .build())
            .build());

    private KubernetesSnapshotVerifier() {
    }

    public enum Stage {
        GATED,
        RUNNING,
        NOT_TERMINAL_YET,
        TERMINAL
    }

    public record Pins(String namespaceName, String namespaceUid, String serviceAccountName, String serviceAccountUid,
            String jobName, String jobUid, String podName, String podUid, String runtimeClass, String runtimeUid,
            String runtimeHandler, String schedulingGate, String podSpecJson, String jobSpecJson,
            String runtimeConfigurationJson, String podMetadataJson, Map<String, String> imageIds) {
        public Pins {
            name(namespaceName);
            name(serviceAccountName);
            name(jobName);
            name(podName);
            name(runtimeClass);
            name(runtimeHandler);
            uid(namespaceUid);
            uid(serviceAccountUid);
            uid(jobUid);
            uid(podUid);
            uid(runtimeUid);
            if (schedulingGate == null || schedulingGate.length() > 316
                    || !schedulingGate.matches("[a-z0-9.-]+/[A-Za-z0-9._-]+") || podSpecJson == null
                    || jobSpecJson == null || runtimeConfigurationJson == null || podMetadataJson == null
                    || imageIds == null || imageIds.isEmpty() || imageIds.size() > 16) {
                throw failed();
            }
            imageIds = Map.copyOf(imageIds);
            for (var entry : imageIds.entrySet()) {
                name(entry.getKey());
                if (entry.getValue() == null || entry.getValue().length() > 1024
                        || !entry.getValue().matches("[A-Za-z0-9._:/@-]*sha256:[0-9a-f]{64}")) {
                    throw failed();
                }
            }
        }

        Pins forPod(String name, String uid) {
            return new Pins(namespaceName, namespaceUid, serviceAccountName, serviceAccountUid, jobName, jobUid, name,
                    uid, runtimeClass, runtimeUid, runtimeHandler, schedulingGate, podSpecJson, jobSpecJson,
                    runtimeConfigurationJson, podMetadataJson, imageIds);
        }
    }

    static void requirePodProfile(Pins pins, ObjectNode pod) {
        identity(pod, "v1", "Pod", pins.podName(), pins.podUid(), pins.namespaceName());
        requirePodMetadataAndOwner(pins, pod);
        var expected = parse(pins.podSpecJson().getBytes(StandardCharsets.UTF_8));
        var spec = object(pod.get("spec")).deepCopy();
        if (!spec.has("schedulingGates")) {
            expected.remove("schedulingGates");
            if (spec.has("nodeName")) {
                name(text(spec, "nodeName"));
                spec.remove("nodeName");
            }
        }
        equal(expected, spec);
    }

    public record Observation(String podUid, String jobUid, String podResourceVersion, String nodeName, Stage stage) {
    }

    public static Observation verifyEligible(Pins pins, byte[] namespace, byte[] account, byte[] job, byte[] pod,
            byte[] runtime) {
        return verify(pins, namespace, account, job, pod, runtime, Stage.GATED);
    }

    public static Observation verifyRunning(Pins pins, byte[] namespace, byte[] account, byte[] job, byte[] pod,
            byte[] runtime) {
        return verify(pins, namespace, account, job, pod, runtime, Stage.RUNNING);
    }

    public static Observation verifyTerminal(Pins pins, byte[] namespace, byte[] account, byte[] job, byte[] pod,
            byte[] runtime) {
        return verify(pins, namespace, account, job, pod, runtime, Stage.TERMINAL);
    }

    public static Observation verifyTerminalProgress(Pins pins, byte[] namespace, byte[] account, byte[] job,
            byte[] pod, byte[] runtime) {
        return verify(pins, namespace, account, job, pod, runtime, Stage.NOT_TERMINAL_YET);
    }

    private static Observation verify(Pins p, byte[] namespace, byte[] account, byte[] job, byte[] pod, byte[] runtime,
            Stage stage) {
        try {
            if (p == null) {
                throw failed();
            }
            var expected = parse(p.podSpecJson().getBytes(StandardCharsets.UTF_8));
            var expectedJob = parse(p.jobSpecJson().getBytes(StandardCharsets.UTF_8));
            requireExpectedProfile(p, expected, expectedJob);
            identity(parse(namespace), "v1", "Namespace", p.namespaceName(), p.namespaceUid(), null);
            identity(parse(account), "v1", "ServiceAccount", p.serviceAccountName(), p.serviceAccountUid(),
                    p.namespaceName());
            var j = parse(job);
            identity(j, "batch/v1", "Job", p.jobName(), p.jobUid(), p.namespaceName());
            equal(expectedJob, object(j.get("spec")));
            boolean terminalJob = terminalJob(j, stage);
            requireRuntime(p, runtime);
            var actual = parse(pod);
            identity(actual, "v1", "Pod", p.podName(), p.podUid(), p.namespaceName());
            requirePodMetadataAndOwner(p, actual);
            var spec = object(actual.get("spec")).deepCopy();
            requireSchedulingGate(p, expected);
            String node = requireStage(p, stage, actual, expected, spec, terminalJob);
            equal(expected, spec);
            return new Observation(text(actual.path("metadata"), "uid"), text(j.path("metadata"), "uid"),
                    text(actual.path("metadata"), "resourceVersion"), node,
                    stage == Stage.NOT_TERMINAL_YET && terminalJob ? Stage.TERMINAL : stage);
        } catch (RuntimeException failed) {
            throw failed();
        }
    }

    private static void requireExpectedProfile(Pins p, ObjectNode expected, ObjectNode expectedJob) {
        equal(p.serviceAccountName(), text(expected, "serviceAccountName"));
        equal(p.runtimeClass(), text(expected, "runtimeClassName"));
        templateMatches(expectedJob, expected);
    }

    private static boolean terminalJob(ObjectNode j, Stage stage) {
        boolean terminalJob = false;
        for (var condition : j.path("status").path("conditions")) {
            if (Set.of("Complete", "Failed").contains(text(condition, "type"))
                    && "True".equals(text(condition, "status"))) {
                if (terminalJob) {
                    throw failed();
                }
                terminalJob = true;
            }
            if (Set.of("Failed", "Complete", "FailureTarget", "SuccessCriteriaMet").contains(text(condition, "type"))
                    && "True".equals(text(condition, "status")) && stage != Stage.TERMINAL
                    && stage != Stage.NOT_TERMINAL_YET) {
                throw failed();
            }
        }
        return terminalJob;
    }

    private static void requireRuntime(Pins p, byte[] runtime) {
        var r = parse(runtime);
        identity(r, "node.k8s.io/v1", "RuntimeClass", p.runtimeClass(), p.runtimeUid(), null);
        equal(p.runtimeHandler(), text(r, "handler"));
        var runtimeConfiguration = r.deepCopy();
        runtimeConfiguration.remove(Set.of("apiVersion", "kind", "metadata"));
        equal(parse(p.runtimeConfigurationJson().getBytes(StandardCharsets.UTF_8)), runtimeConfiguration);
    }

    private static void requirePodMetadataAndOwner(Pins p, ObjectNode actual) {
        var metadata = JSON.createObjectNode();
        for (String field : Set.of("labels", "annotations")) {
            JsonNode value = actual.path("metadata").get(field);
            metadata.set(field, value == null ? JSON.createObjectNode() : object(value));
        }
        equal(parse(p.podMetadataJson().getBytes(StandardCharsets.UTF_8)), metadata);
        var owners = actual.path("metadata").path("ownerReferences");
        if (!owners.isArray() || owners.size() != 1) {
            throw failed();
        }
        var owner = owners.get(0);
        equal("batch/v1", text(owner, "apiVersion"));
        equal("Job", text(owner, "kind"));
        equal(p.jobName(), text(owner, "name"));
        equal(p.jobUid(), text(owner, "uid"));
        if (!owner.path("controller").isBoolean() || !owner.path("controller").booleanValue()) {
            throw failed();
        }
    }

    private static void requireSchedulingGate(Pins p, ObjectNode expected) {
        var gates = expected.path("schedulingGates");
        if (!gates.isArray() || gates.size() != 1 || gates.get(0).size() != 1
                || !p.schedulingGate().equals(text(gates.get(0), "name")) || expected.has("nodeName")) {
            throw failed();
        }
    }

    private static void requireContainerNames(Pins p, Set<String> containers, Set<String> initial) {
        var all = new HashSet<>(containers);
        all.addAll(initial);
        if (containers.isEmpty() || all.size() != containers.size() + initial.size()
                || !all.equals(p.imageIds().keySet())) {
            throw failed();
        }
    }

    private static String requireStage(Pins p, Stage stage, ObjectNode actual, ObjectNode expected, ObjectNode spec,
            boolean terminalJob) {
        Set<String> containers = containerNames(expected.path("containers"));
        Set<String> initial = containerNames(expected.path("initContainers"));
        requireContainerNames(p, containers, initial);
        String node = "";
        if (stage == Stage.RUNNING || stage == Stage.TERMINAL || stage == Stage.NOT_TERMINAL_YET) {
            node = text(spec, "nodeName");
            name(node);
            spec.remove("nodeName");
            expected.remove("schedulingGates");
            if (stage == Stage.RUNNING) {
                equal("Running", text(actual.path("status"), "phase"));
                statuses(actual.path("status").path("containerStatuses"), containers, p.imageIds(), null);
                statuses(actual.path("status").path("initContainerStatuses"), initial, p.imageIds(), expected);
            } else if (stage == Stage.NOT_TERMINAL_YET) {
                requireTerminalProgress(p, actual, expected, containers, initial, terminalJob);
            } else {
                requireTerminalStage(p, actual, expected, containers, initial, terminalJob);
            }
        } else {
            equal("Pending", text(actual.path("status"), "phase"));
        }
        return node;
    }

    private static void requireTerminalStage(Pins p, ObjectNode actual, ObjectNode expected, Set<String> containers,
            Set<String> initial, boolean terminalJob) {
        if (!terminalJob || !Set.of("Succeeded", "Failed").contains(text(actual.path("status"), "phase"))
                || !"Never".equals(text(expected, "restartPolicy")) || expected.has("ephemeralContainers")) {
            throw failed();
        }
        var identities = new HashSet<String>();
        terminalStatuses(actual.path("status").path("containerStatuses"), containers, p.imageIds(), identities);
        terminalStatuses(actual.path("status").path("initContainerStatuses"), initial, p.imageIds(), identities);
        if (actual.path("status").has("ephemeralContainerStatuses")) {
            throw failed();
        }
        requireTerminationProfile(expected);
    }

    private static void requireTerminationProfile(ObjectNode expected) {
        if (!"Never".equals(text(expected, "restartPolicy")) || expected.has("ephemeralContainers")) {
            throw failed();
        }
        for (var container : expected.path("containers")) {
            if (container.has("restartPolicy") || container.has("restartPolicyRules")) {
                throw failed();
            }
        }
        for (var container : expected.path("initContainers")) {
            if (container.has("restartPolicyRules") || container.has("restartPolicy")
                    && !Set.of("Always", "Never").contains(text(container, "restartPolicy"))) {
                throw failed();
            }
        }
    }

    private static void requireTerminalProgress(Pins p, ObjectNode actual, ObjectNode expected, Set<String> containers,
            Set<String> initial, boolean terminalJob) {
        requireTerminationProfile(expected);
        String phase = text(actual.path("status"), "phase");
        if (Set.of("Succeeded", "Failed").contains(phase)) {
            requireTerminalStage(p, actual, expected, containers, initial, true);
            return;
        }
        if (!"Running".equals(phase) || terminalJob || !"Never".equals(text(expected, "restartPolicy"))
                || expected.has("ephemeralContainers") || actual.path("status").has("ephemeralContainerStatuses")) {
            throw failed();
        }
        var identities = new HashSet<String>();
        progressStatuses(actual.path("status").path("containerStatuses"), containers, p.imageIds(), identities, null);
        progressStatuses(actual.path("status").path("initContainerStatuses"), initial, p.imageIds(), identities,
                expected);
    }

    private static void progressStatuses(JsonNode rows, Set<String> expected, Map<String, String> images,
            Set<String> identities, JsonNode initialSpec) {
        if (expected.isEmpty() && rows.isMissingNode()) {
            return;
        }
        if (!rows.isArray() || rows.size() != expected.size()) {
            throw failed();
        }
        var seen = new HashSet<String>();
        for (var row : rows) {
            String name = text(row, "name");
            requireStatusIdentity(row, name, expected, seen, images);
            var state = row.path("state");
            if (!state.isObject() || state.size() != 1) {
                throw failed();
            }
            if (state.path("terminated").isObject()) {
                terminalStatuses(JSON.createArrayNode().add(row), Set.of(name), images, identities);
            } else {
                if (!state.path("running").isObject() || !row.path("started").isBoolean()
                        || !row.path("started").booleanValue() || !sidecar(name, initialSpec)) {
                    throw failed();
                }
                java.time.Instant.parse(text(state.path("running"), "startedAt"));
                containerIdentity(row, identities);
            }
        }
    }

    private static String containerIdentity(JsonNode row, Set<String> identities) {
        String identity = text(row, "containerID");
        if (!identity.matches("[a-z][a-z0-9+.-]{0,31}://[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
                || !identities.add(identity)) {
            throw failed();
        }
        return identity;
    }

    private static void terminalStatuses(JsonNode rows, Set<String> expected, Map<String, String> images,
            Set<String> identities) {
        if (expected.isEmpty() && rows.isMissingNode()) {
            return;
        }
        if (!rows.isArray() || rows.size() != expected.size()) {
            throw failed();
        }
        var seen = new HashSet<String>();
        for (var row : rows) {
            String name = text(row, "name");
            var state = row.path("state");
            var terminated = state.path("terminated");
            if (!expected.contains(name) || !seen.add(name) || !row.path("restartCount").isIntegralNumber()
                    || !row.path("restartCount").canConvertToInt() || row.path("restartCount").intValue() != 0
                    || !state.isObject() || state.size() != 1 || !terminated.isObject()
                    || !terminated.path("exitCode").isIntegralNumber() || !terminated.path("exitCode").canConvertToInt()
                    || "ContainerStatusUnknown".equals(terminated.path("reason").asText())) {
                throw failed();
            }
            equal(images.get(name), text(row, "imageID"));
            String identity = containerIdentity(row, identities);
            equal(identity, text(terminated, "containerID"));
            java.time.Instant.parse(text(terminated, "finishedAt"));
        }
    }

    private static void statuses(JsonNode rows, Set<String> expected, Map<String, String> imageIds, JsonNode initSpec) {
        if (expected.isEmpty() && rows.isMissingNode()) {
            return;
        }
        if (!rows.isArray() || rows.size() != expected.size()) {
            throw failed();
        }
        var seen = new HashSet<String>();
        for (var row : rows) {
            String name = text(row, "name");
            requireStatusIdentity(row, name, expected, seen, imageIds);
            boolean sidecar = sidecar(name, initSpec);
            var state = row.path("state");
            requireRunningOrTerminatedState(row, state, sidecar);
        }
    }

    private static void requireStatusIdentity(JsonNode row, String name, Set<String> expected, Set<String> seen,
            Map<String, String> imageIds) {
        if (!expected.contains(name) || !seen.add(name) || !row.path("restartCount").isIntegralNumber()
                || !row.path("restartCount").canConvertToInt() || row.path("restartCount").intValue() != 0) {
            throw failed();
        }
        equal(imageIds.get(name), text(row, "imageID"));
    }

    private static boolean sidecar(String name, JsonNode initSpec) {
        boolean sidecar = initSpec == null;
        if (initSpec != null) {
            for (var init : initSpec.path("initContainers")) {
                if (name.equals(text(init, "name"))) {
                    sidecar = "Always".equals(init.path("restartPolicy").asText());
                }
            }
        }
        return sidecar;
    }

    private static void requireRunningOrTerminatedState(JsonNode row, JsonNode state, boolean sidecar) {
        if (!state.isObject() || state.size() != 1) {
            throw failed();
        }
        if (sidecar) {
            if (!state.path("running").isObject() || !row.path("started").isBoolean()
                    || !row.path("started").booleanValue() || !row.path("ready").isBoolean()
                    || !row.path("ready").booleanValue()) {
                throw failed();
            }
        } else if (!state.path("terminated").path("exitCode").isIntegralNumber()
                || !state.path("terminated").path("exitCode").canConvertToInt()
                || state.path("terminated").path("exitCode").intValue() != 0) {
            throw failed();
        }
    }

    static void templateMatches(JsonNode job, JsonNode pod) {
        var template = object(job.path("template").get("spec")).deepCopy();
        var admitted = object(pod).deepCopy();
        Set<String> admissionFields = Set.of("priority", "preemptionPolicy", "tolerations", "overhead");
        template.remove(admissionFields);
        admitted.remove(admissionFields);
        equal(template, admitted);
    }

    static Set<String> containerNames(JsonNode rows) {
        var names = new HashSet<String>();
        if (rows.isMissingNode()) {
            return names;
        }
        if (!rows.isArray() || rows.size() > 16) {
            throw failed();
        }
        for (var row : rows) {
            String value = text(row, "name");
            name(value);
            if (!names.add(value)) {
                throw failed();
            }
        }
        return names;
    }

    private static void identity(JsonNode value, String api, String kind, String name, String uid, String namespace) {
        equal(api, text(value, "apiVersion"));
        equal(kind, text(value, "kind"));
        var metadata = object(value.get("metadata"));
        equal(name, text(metadata, "name"));
        String actualUid = text(metadata, "uid");
        uid(actualUid);
        if (uid != null) {
            equal(uid, actualUid);
        }
        text(metadata, "resourceVersion");
        if (metadata.hasNonNull("deletionTimestamp")) {
            throw failed();
        }
        if (namespace == null) {
            if (metadata.hasNonNull("namespace")) {
                throw failed();
            }
        } else {
            equal(namespace, text(metadata, "namespace"));
        }
    }

    static ObjectNode parse(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAXIMUM) {
            throw failed();
        }
        try (var parser = JSON
                .createParser(StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString())) {
            var value = object(JSON.readTree(parser));
            if (parser.nextToken() != null) {
                throw failed();
            }
            return value;
        } catch (Exception failed) {
            throw failed();
        }
    }

    private static ObjectNode object(JsonNode value) {
        if (!(value instanceof ObjectNode result)) {
            throw failed();
        }
        return result;
    }

    static String text(JsonNode value, String field) {
        var item = value.get(field);
        if (item == null || !item.isTextual() || item.textValue().isBlank() || item.textValue().length() > 1024) {
            throw failed();
        }
        return item.textValue();
    }

    private static void name(String value) {
        if (value == null || value.length() > 253 || !value.matches("[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?")) {
            throw failed();
        }
    }

    private static void uid(String value) {
        try {
            if (!UUID.fromString(value).toString().equals(value)) {
                throw failed();
            }
        } catch (RuntimeException failed) {
            throw failed();
        }
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw failed();
        }
    }

    private static ObservationFailure failed() {
        return new ObservationFailure();
    }
}
