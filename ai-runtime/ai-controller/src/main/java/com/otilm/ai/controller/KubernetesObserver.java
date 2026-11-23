package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Performs current authenticated API reads; the result grants no registration or business authority. */
public final class KubernetesObserver {
    private KubernetesObserver() {
    }

    public record Versions(String namespace, String serviceAccount, String job, String podList, String runtimeClass) {
    }

    public record Evidence(KubernetesSnapshotVerifier.Observation workload, Versions versions) {
    }

    public static Evidence observe(KubernetesApi api, KubernetesSnapshotVerifier.Pins pins,
            KubernetesSnapshotVerifier.Stage stage) {
        if (api == null || pins == null || stage == null || api.cleanupUncertain()) {
            throw new ObservationFailure();
        }
        byte[] namespace = api.namespace(pins.namespaceName());
        byte[] account = api.serviceAccount(pins.namespaceName(), pins.serviceAccountName());
        byte[] job = api.job(pins.namespaceName(), pins.jobName());
        byte[] pods = api.pods(pins.namespaceName());
        var listed = uniqueOwnedPod(pods, pins);
        byte[] runtime = api.runtimeClass(pins.runtimeClass());
        byte[] pod = api.pod(pins.namespaceName(), pins.podName());
        var firstPod = KubernetesSnapshotVerifier.parse(pod);
        boolean progressed = !properties(listed).equals(properties(firstPod));
        if (progressed && stage != KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET) {
            throw new ObservationFailure();
        }
        var observation = switch (stage) {
            case GATED -> KubernetesSnapshotVerifier.verifyEligible(pins, namespace, account, job, pod, runtime);
            case RUNNING -> KubernetesSnapshotVerifier.verifyRunning(pins, namespace, account, job, pod, runtime);
            case TERMINAL -> KubernetesSnapshotVerifier.verifyTerminal(pins, namespace, account, job, pod, runtime);
            case NOT_TERMINAL_YET ->
                KubernetesSnapshotVerifier.verifyTerminalProgress(pins, namespace, account, job, pod, runtime);
        };
        if (progressed) {
            KubernetesSnapshotVerifier
                    .verifyTerminalProgress(pins, namespace, account, job, listedPod(listed), runtime);
            requireProgressOnly(listed, firstPod);
        }
        unchanged(namespace, api.namespace(pins.namespaceName()));
        unchanged(account, api.serviceAccount(pins.namespaceName(), pins.serviceAccountName()));
        unchanged(runtime, api.runtimeClass(pins.runtimeClass()));
        byte[] currentJob = api.job(pins.namespaceName(), pins.jobName());
        byte[] currentPods = api.pods(pins.namespaceName());
        var currentListed = uniqueOwnedPod(currentPods, pins);
        if (progressed || !KubernetesSnapshotVerifier.parse(job).equals(KubernetesSnapshotVerifier.parse(currentJob))
                || !items(pods).equals(items(currentPods))) {
            if (stage != KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET) {
                throw new ObservationFailure();
            }
            KubernetesSnapshotVerifier
                    .verifyTerminalProgress(pins, namespace, account, currentJob, listedPod(currentListed), runtime);
            byte[] currentPod = api.pod(pins.namespaceName(), pins.podName());
            var current = KubernetesSnapshotVerifier
                    .verifyTerminalProgress(pins, namespace, account, currentJob, currentPod, runtime);
            var currentObject = KubernetesSnapshotVerifier.parse(currentPod);
            requireProgressOnly(KubernetesSnapshotVerifier.parse(job), KubernetesSnapshotVerifier.parse(currentJob));
            requireProgressOnly(firstPod, currentObject);
            var before = ownedPods(pods, pins);
            var after = ownedPods(currentPods, pins);
            if (!before.keySet().equals(after.keySet())) {
                throw new ObservationFailure();
            }
            before.forEach((uid, podBefore) -> requireProgressOnly(podBefore, after.get(uid)));
            requireProgressOnly(currentListed, currentObject);
            observation = new KubernetesSnapshotVerifier.Observation(current.podUid(), current.jobUid(),
                    current.podResourceVersion(), current.nodeName(),
                    KubernetesSnapshotVerifier.Stage.NOT_TERMINAL_YET);
            job = currentJob;
            pods = currentPods;
        }
        api.remaining();
        return new Evidence(observation,
                new Versions(version(namespace), version(account), version(job), version(pods), version(runtime)));
    }

    private static byte[] listedPod(ObjectNode listed) {
        var pod = listed.deepCopy();
        pod.put("apiVersion", "v1").put("kind", "Pod");
        return pod.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void requireProgressOnly(ObjectNode before, ObjectNode after) {
        if (!progressProperties(before).equals(progressProperties(after))
                || !containerIdentities(before).equals(containerIdentities(after))) {
            throw new ObservationFailure();
        }
    }

    private static ObjectNode progressProperties(ObjectNode resource) {
        var result = properties(resource);
        result.remove("status");
        var metadata = (ObjectNode) result.get("metadata");
        metadata.remove("resourceVersion");
        validateManagedFields(metadata.remove("managedFields"));
        normalizeFinalizers(metadata, metadata.remove("finalizers"));
        return result;
    }

    private static void validateManagedFields(JsonNode managed) {
        if (managed != null) {
            if (!managed.isArray()) {
                throw new ObservationFailure();
            }
            for (var entry : managed) {
                if (!entry.isObject()) {
                    throw new ObservationFailure();
                }
            }
        }
    }

    private static void normalizeFinalizers(ObjectNode metadata, JsonNode finalizers) {
        var retained = metadata.putArray("finalizers");
        if (finalizers != null) {
            if (!finalizers.isArray()) {
                throw new ObservationFailure();
            }
            var seen = new HashSet<String>();
            for (var value : finalizers) {
                if (!value.isTextual() || value.textValue().isBlank() || !seen.add(value.textValue())) {
                    throw new ObservationFailure();
                }
                if (!"batch.kubernetes.io/job-tracking".equals(value.textValue())) {
                    retained.add(value);
                }
            }
        }
    }

    private static Map<String, String> containerIdentities(ObjectNode resource) {
        var result = new HashMap<String, String>();
        for (String field : new String[]{"containerStatuses", "initContainerStatuses"}) {
            for (var row : resource.path("status").path(field)) {
                String name = KubernetesSnapshotVerifier.text(row, "name");
                if (result.put(name, KubernetesSnapshotVerifier.text(row, "containerID")) != null) {
                    throw new ObservationFailure();
                }
            }
        }
        return result;
    }

    private static String version(byte[] bytes) {
        return KubernetesSnapshotVerifier
                .text(KubernetesSnapshotVerifier.parse(bytes).path("metadata"), "resourceVersion");
    }

    private static void unchanged(byte[] before, byte[] after) {
        if (!KubernetesSnapshotVerifier.parse(before).equals(KubernetesSnapshotVerifier.parse(after))) {
            throw new ObservationFailure();
        }
    }

    private static ObjectNode properties(ObjectNode pod) {
        var result = pod.deepCopy();
        result.remove(Set.of("apiVersion", "kind"));
        return result;
    }

    private static ArrayNode items(byte[] bytes) {
        var rows = ((ArrayNode) KubernetesSnapshotVerifier.parse(bytes).get("items")).deepCopy();
        for (JsonNode row : rows) {
            ((ObjectNode) row).remove(Set.of("apiVersion", "kind"));
        }
        return rows;
    }

    private static ObjectNode uniqueOwnedPod(byte[] bytes, KubernetesSnapshotVerifier.Pins pins) {
        var owned = ownedPods(bytes, pins);
        for (var pod : owned.values()) {
            KubernetesSnapshotVerifier
                    .requirePodProfile(
                            pins
                                    .forPod(KubernetesSnapshotVerifier.text(pod.path("metadata"), "name"),
                                            KubernetesSnapshotVerifier.text(pod.path("metadata"), "uid")),
                            KubernetesSnapshotVerifier.parse(listedPod(pod)));
        }
        var selected = owned.get(pins.podUid());
        if (selected == null || !pins.podName().equals(selected.path("metadata").path("name").asText())) {
            throw new ObservationFailure();
        }
        return selected;
    }

    static Map<String, ObjectNode> ownedPods(byte[] bytes, KubernetesSnapshotVerifier.Pins pins) {
        var list = KubernetesSnapshotVerifier.parse(bytes);
        requireCompletePodList(list);
        var owned = new LinkedHashMap<String, ObjectNode>();
        var names = new HashSet<String>();
        for (JsonNode row : list.path("items")) {
            requirePodListEntry(row, pins);
            for (JsonNode owner : row.path("metadata").path("ownerReferences")) {
                if (pins.jobUid().equals(owner.path("uid").asText())
                        || pins.jobName().equals(owner.path("name").asText())
                                && "Job".equals(owner.path("kind").asText())) {
                    var pod = (ObjectNode) row;
                    String uid = KubernetesSnapshotVerifier.text(pod.path("metadata"), "uid");
                    String name = KubernetesSnapshotVerifier.text(pod.path("metadata"), "name");
                    pins.forPod(name, uid);
                    var owners = pod.path("metadata").path("ownerReferences");
                    if (!owners.isArray() || owners.size() != 1 || !"batch/v1".equals(owner.path("apiVersion").asText())
                            || !"Job".equals(owner.path("kind").asText())
                            || !pins.jobName().equals(owner.path("name").asText())
                            || !pins.jobUid().equals(owner.path("uid").asText())
                            || !owner.path("controller").isBoolean() || !owner.path("controller").booleanValue()) {
                        throw new ObservationFailure();
                    }
                    if (owned.putIfAbsent(uid, pod) != null || !names.add(name) || owned.size() > 16) {
                        throw new ObservationFailure();
                    }
                }
            }
        }
        return owned;
    }

    private static void requireCompletePodList(ObjectNode list) {
        if (!"v1".equals(KubernetesSnapshotVerifier.text(list, "apiVersion"))
                || !"PodList".equals(KubernetesSnapshotVerifier.text(list, "kind")) || !list.path("metadata").isObject()
                || !list.path("items").isArray() || list.path("items").size() > 64
                || list.path("metadata").hasNonNull("continue") && (!list.path("metadata").path("continue").isTextual()
                        || !list.path("metadata").path("continue").textValue().isEmpty())
                || list.path("metadata").hasNonNull("remainingItemCount")
                        && (!list.path("metadata").path("remainingItemCount").isIntegralNumber()
                                || !list.path("metadata").path("remainingItemCount").canConvertToInt()
                                || list.path("metadata").path("remainingItemCount").intValue() != 0)) {
            throw new ObservationFailure();
        }
        KubernetesSnapshotVerifier.text(list.path("metadata"), "resourceVersion");
    }

    private static void requirePodListEntry(JsonNode pod, KubernetesSnapshotVerifier.Pins pins) {
        if (pod.has("apiVersion") && !"v1".equals(KubernetesSnapshotVerifier.text(pod, "apiVersion"))
                || pod.has("kind") && !"Pod".equals(KubernetesSnapshotVerifier.text(pod, "kind"))
                || !pins.namespaceName().equals(KubernetesSnapshotVerifier.text(pod.path("metadata"), "namespace"))) {
            throw new ObservationFailure();
        }
    }

}
