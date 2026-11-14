package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Administrator literal recipe; parsing supplies no current workload or business authority. */
public final class ControllerProfile {
    private final ObjectNode canonical;
    private final ObjectNode runtime;
    private final String name;
    private final String job;
    private final String jobSpec;
    private final String podSpec;
    private final String metadata;
    private final String runtimeConfiguration;
    private final Map<String, String> imageIds;

    private ControllerProfile(ObjectNode document) {
        var root = ControllerConfiguration
                .fields(document, Set.of("version", "pins", "runtime", "job", "podSpec", "podMetadata", "imageIds"));
        require(root.path("version").isIntegralNumber() && root.path("version").canConvertToInt()
                && root.path("version").intValue() == 1);
        canonical = ControllerConfiguration
                .fields(root.get("pins"),
                        Set
                                .of("cluster", "namespaceName", "namespaceUid", "serviceAccountName",
                                        "serviceAccountUid", "runtimeClass", "imageDigest", "templateDigest",
                                        "profileRevision", "securityRevision", "trustRevision", "protocol"));
        ControllerWire.name(text(canonical, "cluster"), 63, false);
        ControllerWire.name(text(canonical, "namespaceName"), 63, false);
        ControllerWire.name(text(canonical, "serviceAccountName"), 253, true);
        ControllerWire.name(text(canonical, "runtimeClass"), 253, true);
        ControllerWire.id(canonical, "namespaceUid");
        ControllerWire.id(canonical, "serviceAccountUid");
        ControllerWire.digest(text(canonical, "imageDigest"));
        ControllerWire.digest(text(canonical, "templateDigest"));
        for (String field : Set.of("profileRevision", "securityRevision", "trustRevision")) {
            ControllerWire.number(canonical, field);
        }
        require("v1".equals(text(canonical, "protocol")));
        runtime = ControllerConfiguration
                .fields(root.get("runtime"), Set.of("uid", "handler", "schedulingGate", "configuration"));
        ControllerWire.id(runtime, "uid");
        ControllerWire.name(text(runtime, "handler"), 253, true);
        String gate = text(runtime, "schedulingGate");
        require(gate.length() <= 316 && gate.matches("[a-z0-9.-]+/[A-Za-z0-9._-]+"));
        require(runtime.path("configuration").isObject()
                && text(runtime, "handler").equals(text(runtime.path("configuration"), "handler")));
        runtimeConfiguration = runtime.path("configuration").toString();
        var literal = ControllerConfiguration.fields(root.get("job"), Set.of("apiVersion", "kind", "metadata", "spec"));
        require("batch/v1".equals(text(literal, "apiVersion")) && "Job".equals(text(literal, "kind")));
        var jobMetadata = object(literal.get("metadata"));
        name = text(jobMetadata, "name");
        ControllerWire.name(name, 63, false);
        require(text(canonical, "namespaceName").equals(text(jobMetadata, "namespace")));
        var keys = jobMetadata.fieldNames();
        while (keys.hasNext()) {
            require(Set.of("name", "namespace", "labels", "annotations").contains(keys.next()));
        }
        var expectedPod = object(root.get("podSpec"));
        require(text(canonical, "serviceAccountName").equals(text(expectedPod, "serviceAccountName"))
                && text(canonical, "runtimeClass").equals(text(expectedPod, "runtimeClassName")));
        var expectedJob = object(literal.get("spec"));
        KubernetesSnapshotVerifier.templateMatches(expectedJob, expectedPod);
        var gates = expectedPod.path("schedulingGates");
        require(gates.isArray() && gates.size() == 1 && gates.get(0).size() == 1
                && gate.equals(text(gates.get(0), "name")) && !expectedPod.has("nodeName"));
        var podMetadata = ControllerConfiguration.fields(root.get("podMetadata"), Set.of("labels", "annotations"));
        object(podMetadata.get("labels"));
        object(podMetadata.get("annotations"));
        metadata = podMetadata.toString();
        imageIds = images(object(root.get("imageIds")));
        var containers = KubernetesSnapshotVerifier.containerNames(expectedPod.path("containers"));
        var initial = KubernetesSnapshotVerifier.containerNames(expectedPod.path("initContainers"));
        var all = new HashSet<>(containers);
        all.addAll(initial);
        require(!containers.isEmpty() && all.size() == containers.size() + initial.size()
                && all.equals(imageIds.keySet()));
        job = literal.toString();
        jobSpec = expectedJob.toString();
        podSpec = expectedPod.toString();
    }

    public static ControllerProfile read(Path file) {
        try {
            return new ControllerProfile(ControllerConfiguration.document(file, 1_048_576));
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    public void requireLaunch(ControllerWire.Launch launch) {
        require(launch != null && name.equals(launch.jobName()) && text(canonical, "cluster").equals(launch.cluster())
                && text(canonical, "namespaceName").equals(launch.namespaceName())
                && ControllerWire.id(canonical, "namespaceUid").equals(launch.namespaceUid())
                && text(canonical, "serviceAccountName").equals(launch.serviceAccountName())
                && ControllerWire.id(canonical, "serviceAccountUid").equals(launch.serviceAccountUid())
                && text(canonical, "runtimeClass").equals(launch.runtimeClass())
                && text(canonical, "imageDigest").equals(launch.imageDigest())
                && text(canonical, "templateDigest").equals(launch.templateDigest())
                && ControllerWire.number(canonical, "profileRevision") == launch.profileRevision()
                && ControllerWire.number(canonical, "securityRevision") == launch.securityRevision()
                && ControllerWire.number(canonical, "trustRevision") == launch.trustRevision()
                && text(canonical, "protocol").equals(launch.protocol()));
    }

    public void requireRunnerDeadline() {
        var expectedPod = KubernetesSnapshotVerifier.parse(podSpec.getBytes(StandardCharsets.UTF_8));
        var expectedJob = KubernetesSnapshotVerifier.parse(jobSpec.getBytes(StandardCharsets.UTF_8));
        for (var limit : Map.of("activeDeadlineSeconds", 27, "terminationGracePeriodSeconds", 1).entrySet()) {
            var value = expectedPod.path(limit.getKey());
            require(value.isIntegralNumber() && value.canConvertToInt() && value.intValue() == limit.getValue());
        }
        var retries = expectedJob.path("backoffLimit");
        require(retries.isIntegralNumber() && retries.canConvertToInt() && retries.intValue() == 0);
        require("Never".equals(text(expectedPod, "restartPolicy")) && !expectedJob.has("activeDeadlineSeconds")
                && !expectedJob.has("ttlSecondsAfterFinished"));
    }

    String cluster() {
        return text(canonical, "cluster");
    }

    String namespaceName() {
        return text(canonical, "namespaceName");
    }

    String jobName() {
        return name;
    }

    public byte[] job() {
        return job.getBytes(StandardCharsets.UTF_8);
    }

    public KubernetesSnapshotVerifier.Pins pins(String jobUid, String podName, String podUid) {
        return new KubernetesSnapshotVerifier.Pins(text(canonical, "namespaceName"), text(canonical, "namespaceUid"),
                text(canonical, "serviceAccountName"), text(canonical, "serviceAccountUid"), name, jobUid, podName,
                podUid, text(canonical, "runtimeClass"), text(runtime, "uid"), text(runtime, "handler"),
                text(runtime, "schedulingGate"), podSpec, jobSpec, runtimeConfiguration, metadata, imageIds);
    }

    public Optional<KubernetesSnapshotVerifier.Pins> findPod(byte[] list, String jobUid) {
        var found = findPods(list, jobUid);
        require(found.size() <= 1);
        return found.stream().findFirst();
    }

    public List<KubernetesSnapshotVerifier.Pins> findPods(byte[] list, String jobUid) {
        var template = pins(jobUid, name, jobUid);
        return KubernetesObserver
                .ownedPods(list, template)
                .values()
                .stream()
                .map(pod -> template.forPod(text(pod.path("metadata"), "name"), text(pod.path("metadata"), "uid")))
                .toList();
    }

    private static Map<String, String> images(ObjectNode object) {
        require(!object.isEmpty() && object.size() <= 16);
        var values = new HashMap<String, String>();
        object.fields().forEachRemaining(entry -> {
            ControllerWire.name(entry.getKey(), 63, false);
            String value = KubernetesSnapshotVerifier.text(object, entry.getKey());
            require(value.length() <= 1024 && value.matches("[A-Za-z0-9._:/@-]*sha256:[0-9a-f]{64}"));
            values.put(entry.getKey(), value);
        });
        return Map.copyOf(values);
    }

    private static ObjectNode object(JsonNode value) {
        require(value instanceof ObjectNode);
        return (ObjectNode) value;
    }

    private static String text(JsonNode value, String field) {
        return ControllerWire.text(value, field);
    }

    private static void require(boolean accepted) {
        if (!accepted) {
            throw new ObservationFailure();
        }
    }
}
