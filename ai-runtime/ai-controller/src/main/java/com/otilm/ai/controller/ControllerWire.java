package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Closed controller metadata; labels and decoded values confer no native identity or business authority. */
public final class ControllerWire {
    private static final int MAXIMUM = 4096;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> LOCATOR_FIELDS = Set.of("version", "kind", "correlationId", "runId", "attemptId");
    private static final Set<String> LAUNCH_FIELDS = Set
            .of("version", "kind", "correlationId", "runId", "attemptId", "runRevision", "fence", "launchDeadline",
                    "maxDeadline", "imageDigest", "profileRevision", "securityRevision", "trustRevision", "protocol",
                    "cluster", "namespaceName", "namespaceUid", "serviceAccountName", "serviceAccountUid",
                    "templateDigest", "runtimeClass", "jobName");
    private static final Set<String> OBSERVATION_FIELDS = Set
            .of("version", "kind", "correlationId", "runId", "attemptId", "podUid");
    private static final Set<String> OBSERVATION_REPLY_FIELDS = Set
            .of("version", "kind", "correlationId", "runId", "attemptId", "podUid", "jobUid", "podResourceVersion",
                    "runRevision", "fence", "observationSequence", "validUntil");

    private ControllerWire() {
    }

    public record Locator(UUID correlationId, UUID runId, UUID attemptId) {
        public Locator {
            uuid(correlationId);
            uuid(runId);
            uuid(attemptId);
        }
    }

    public record Launch(Locator locator, long runRevision, long fence, Instant launchDeadline, Instant maxDeadline,
            String imageDigest, long profileRevision, long securityRevision, long trustRevision, String protocol,
            String cluster, String namespaceName, UUID namespaceUid, String serviceAccountName, UUID serviceAccountUid,
            String templateDigest, String runtimeClass, String jobName) {
        public Launch {
            require(locator != null && launchDeadline != null && maxDeadline != null);
            require(!launchDeadline.isAfter(maxDeadline));
            positive(runRevision);
            positive(fence);
            positive(profileRevision);
            positive(securityRevision);
            positive(trustRevision);
            require("v1".equals(protocol));
            digest(imageDigest);
            digest(templateDigest);
            name(cluster, 63, false);
            name(namespaceName, 63, false);
            name(serviceAccountName, 253, true);
            name(runtimeClass, 253, true);
            uuid(namespaceUid);
            uuid(serviceAccountUid);
            require(("ilm-ai-" + locator.attemptId().toString().replace("-", "")).equals(jobName));
        }
    }

    public enum Operation {
        ELIGIBLE,
        REGISTER
    }

    public record ObservationRequest(Locator locator, UUID podUid) {
        public ObservationRequest {
            require(locator != null);
            uuid(podUid);
        }
    }

    public record ObservationReply(ObservationRequest request, UUID jobUid, String podResourceVersion, long runRevision,
            long fence, long observationSequence, Instant validUntil) {
        public ObservationReply {
            require(request != null && validUntil != null);
            uuid(jobUid);
            require(podResourceVersion != null && podResourceVersion.matches("[A-Za-z0-9._:-]{1,128}"));
            positive(runRevision);
            positive(fence);
            positive(observationSequence);
        }
    }

    public enum ControlOperation {
        STATUS,
        FENCE,
        TERMINAL,
        CLEANUP
    }

    public record Pod(String cluster, UUID podUid) {
        public Pod {
            name(cluster, 63, false);
            uuid(podUid);
        }
    }

    public record Control(Locator locator, long runRevision, long fence, UUID jobUid, Set<Pod> workloads) {
        public Control {
            require(locator != null && workloads != null && workloads.size() <= 16);
            positive(runRevision);
            positive(fence);
            if (jobUid != null) {
                uuid(jobUid);
            }
            workloads = Set.copyOf(workloads);
        }
    }

    public record ControlReply(Control control, String runState, String attemptState, Instant validUntil) {
        public ControlReply {
            require(control != null);
        }
    }

    public record CleanupResumeReply(Control control, boolean done) {
        public CleanupResumeReply {
            require(control != null && control.jobUid() != null && !control.workloads().isEmpty());
        }
    }

    public static byte[] cleanupResumeRequest(Locator locator) {
        return write(base("cleanup-resume", locator));
    }

    public static Locator readCleanupResumeRequest(byte[] body) {
        return locator(read(body, LOCATOR_FIELDS, "cleanup-resume"));
    }

    public static CleanupResumeReply readCleanupResumeReply(byte[] body, Locator locator) {
        try {
            return new CleanupResumeReply(readControlReply(body, ControlOperation.FENCE, locator).control(), false);
        } catch (ObservationFailure invalidRequired) {
            return new CleanupResumeReply(readControlReply(body, ControlOperation.CLEANUP, locator).control(), true);
        }
    }

    public record ControlRequest(Locator locator, Control expected) {
        public ControlRequest {
            require(locator != null && (expected == null || locator.equals(expected.locator())));
        }
    }

    public static ControlRequest readControlRequest(byte[] body, ControlOperation operation) {
        require(operation != null);
        var fields = new HashSet<>(LOCATOR_FIELDS);
        boolean bound = operation == ControlOperation.TERMINAL || operation == ControlOperation.CLEANUP;
        if (bound) {
            fields.addAll(Set.of("runRevision", "fence", "jobUid", "workloads"));
        }
        var root = read(body, fields, controlKind(operation, false));
        var locator = locator(root);
        var expected = bound ? control(root, locator) : null;
        require(!bound || expected.jobUid() != null);
        return new ControlRequest(locator, expected);
    }

    public static byte[] controlRequest(ControlOperation operation, Locator locator, Control expected) {
        require(operation != null);
        var body = base(controlKind(operation, false), locator);
        if (operation == ControlOperation.TERMINAL || operation == ControlOperation.CLEANUP) {
            require(expected != null && expected.jobUid() != null && locator.equals(expected.locator()));
            controlFields(body, expected);
        } else {
            require(expected == null);
        }
        return write(body);
    }

    public static ControlReply readControlReply(byte[] body, ControlOperation operation, Locator expected) {
        try {
            require(operation != null);
            var fields = new HashSet<>(LOCATOR_FIELDS);
            fields.addAll(Set.of("runRevision", "fence", "jobUid", "workloads"));
            if (operation == ControlOperation.STATUS) {
                fields.addAll(Set.of("runState", "attemptState"));
            } else if (operation == ControlOperation.TERMINAL) {
                fields.add("validUntil");
            }
            var root = read(body, fields, controlKind(operation, true));
            var locator = locator(root);
            require(locator.equals(expected));
            var control = control(root, locator);
            require(operation != ControlOperation.TERMINAL && operation != ControlOperation.CLEANUP
                    || control.jobUid() != null);
            String run = null;
            String attempt = null;
            Instant validUntil = null;
            if (operation == ControlOperation.STATUS) {
                run = text(root, "runState");
                attempt = text(root, "attemptState");
                require(Set.of("QUEUED", "RUNNING", "FAILED", "CANCELLED", "LIMIT_REACHED").contains(run)
                        && Set.of("LAUNCHING", "CLAIMED", "FENCED").contains(attempt));
            } else if (operation == ControlOperation.TERMINAL) {
                validUntil = timestamp(root, "validUntil");
            }
            return new ControlReply(control, run, attempt, validUntil);
        } catch (RuntimeException unavailable) {
            throw new ObservationFailure();
        }
    }

    private static Control control(JsonNode root, Locator locator) {
        var rows = root.path("workloads");
        require(rows.isArray() && rows.size() <= 16);
        var pods = new HashSet<Pod>();
        for (var row : rows) {
            require(row.isObject() && row.size() == 2 && pods.add(new Pod(text(row, "cluster"), id(row, "podUid"))));
        }
        return new Control(locator, number(root, "runRevision"), number(root, "fence"),
                root.path("jobUid").isNull() ? null : id(root, "jobUid"), pods);
    }

    public static byte[] controlReply(ControlOperation operation, ControlReply reply) {
        require(operation != null && reply != null);
        var root = base(controlKind(operation, true), reply.control().locator());
        controlFields(root, reply.control());
        if (operation == ControlOperation.STATUS) {
            require(reply.runState() != null && reply.attemptState() != null);
            root.put("runState", reply.runState()).put("attemptState", reply.attemptState());
        } else if (operation == ControlOperation.TERMINAL) {
            require(reply.validUntil() != null);
            root.put("validUntil", reply.validUntil().toString());
        }
        byte[] bytes = write(root);
        readControlReply(bytes, operation, reply.control().locator());
        return bytes;
    }

    private static void controlFields(ObjectNode root, Control control) {
        root.put("runRevision", control.runRevision()).put("fence", control.fence());
        if (control.jobUid() == null) {
            root.putNull("jobUid");
        } else {
            root.put("jobUid", control.jobUid().toString());
        }
        var array = root.putArray("workloads");
        control
                .workloads()
                .stream()
                .sorted(java.util.Comparator.comparing(Pod::cluster).thenComparing(p -> p.podUid().toString()))
                .forEach(p -> array.addObject().put("cluster", p.cluster()).put("podUid", p.podUid().toString()));
    }

    private static String controlKind(ControlOperation operation, boolean reply) {
        return switch (operation) {
            case STATUS -> "workload-status";
            case FENCE -> reply ? "cleanup-required" : "cleanup-request";
            case TERMINAL -> reply ? "cleanup-terminal-observed" : "cleanup-terminal-status";
            case CLEANUP -> reply ? "cleanup-recorded" : "cleanup-reconcile";
        };
    }

    public static byte[] observationRequest(Operation operation, ObservationRequest request) {
        require(request != null);
        return write(base(requestKind(operation), request.locator()).put("podUid", request.podUid().toString()));
    }

    public static ObservationRequest readObservationRequest(byte[] body, Operation operation) {
        var root = read(body, OBSERVATION_FIELDS, requestKind(operation));
        return new ObservationRequest(locator(root), id(root, "podUid"));
    }

    public static byte[] observationReply(Operation operation, ObservationReply reply) {
        require(reply != null);
        return write(base(replyKind(operation), reply.request().locator())
                .put("podUid", reply.request().podUid().toString())
                .put("jobUid", reply.jobUid().toString())
                .put("podResourceVersion", reply.podResourceVersion())
                .put("runRevision", reply.runRevision())
                .put("fence", reply.fence())
                .put("observationSequence", reply.observationSequence())
                .put("validUntil", reply.validUntil().toString()));
    }

    public static ObservationReply readObservationReply(byte[] body, Operation operation, ObservationRequest expected) {
        try {
            var root = read(body, OBSERVATION_REPLY_FIELDS, replyKind(operation));
            var request = new ObservationRequest(locator(root), id(root, "podUid"));
            require(request.equals(expected));
            return new ObservationReply(request, id(root, "jobUid"), text(root, "podResourceVersion"),
                    number(root, "runRevision"), number(root, "fence"), number(root, "observationSequence"),
                    timestamp(root, "validUntil"));
        } catch (RuntimeException unavailable) {
            throw new ObservationFailure();
        }
    }

    private static String requestKind(Operation operation) {
        require(operation != null);
        return switch (operation) {
            case ELIGIBLE -> "workload-eligible";
            case REGISTER -> "workload-register";
        };
    }

    private static String replyKind(Operation operation) {
        require(operation != null);
        return switch (operation) {
            case ELIGIBLE -> "workload-eligible";
            case REGISTER -> "workload-registered";
        };
    }

    public static byte[] launchRequest(Locator locator) {
        return write(base("launch-reconcile", locator));
    }

    public static Locator readLaunchRequest(byte[] body) {
        return locator(read(body, LOCATOR_FIELDS, "launch-reconcile"));
    }

    public static byte[] launchReply(Launch launch) {
        require(launch != null);
        var reply = base("launch-binding", launch.locator())
                .put("runRevision", launch.runRevision())
                .put("fence", launch.fence())
                .put("launchDeadline", launch.launchDeadline().toString())
                .put("maxDeadline", launch.maxDeadline().toString())
                .put("imageDigest", launch.imageDigest())
                .put("profileRevision", launch.profileRevision())
                .put("securityRevision", launch.securityRevision())
                .put("trustRevision", launch.trustRevision())
                .put("protocol", launch.protocol())
                .put("cluster", launch.cluster())
                .put("namespaceName", launch.namespaceName())
                .put("namespaceUid", launch.namespaceUid().toString())
                .put("serviceAccountName", launch.serviceAccountName())
                .put("serviceAccountUid", launch.serviceAccountUid().toString())
                .put("templateDigest", launch.templateDigest())
                .put("runtimeClass", launch.runtimeClass())
                .put("jobName", launch.jobName());
        return write(reply);
    }

    public static Launch readLaunchReply(byte[] body, Locator expected) {
        try {
            var reply = read(body, LAUNCH_FIELDS, "launch-binding");
            var locator = locator(reply);
            require(locator.equals(expected));
            return new Launch(locator, number(reply, "runRevision"), number(reply, "fence"),
                    timestamp(reply, "launchDeadline"), timestamp(reply, "maxDeadline"), text(reply, "imageDigest"),
                    number(reply, "profileRevision"), number(reply, "securityRevision"), number(reply, "trustRevision"),
                    text(reply, "protocol"), text(reply, "cluster"), text(reply, "namespaceName"),
                    id(reply, "namespaceUid"), text(reply, "serviceAccountName"), id(reply, "serviceAccountUid"),
                    text(reply, "templateDigest"), text(reply, "runtimeClass"), text(reply, "jobName"));
        } catch (RuntimeException unavailable) {
            throw new ObservationFailure();
        }
    }

    private static ObjectNode base(String kind, Locator locator) {
        require(locator != null);
        return JSON
                .createObjectNode()
                .put("version", 1)
                .put("kind", kind)
                .put("correlationId", locator.correlationId().toString())
                .put("runId", locator.runId().toString())
                .put("attemptId", locator.attemptId().toString());
    }

    private static byte[] write(ObjectNode node) {
        try {
            byte[] bytes = JSON.writeValueAsBytes(node);
            require(bytes.length <= MAXIMUM);
            return bytes;
        } catch (Exception unavailable) {
            throw new ObservationFailure();
        }
    }

    private static ObjectNode read(byte[] body, Set<String> expected, String kind) {
        require(body != null && body.length > 0 && body.length <= MAXIMUM);
        var root = KubernetesSnapshotVerifier.parse(body);
        var fields = new HashSet<String>();
        root.fieldNames().forEachRemaining(fields::add);
        require(fields.equals(expected) && root.path("version").isIntegralNumber()
                && root.path("version").canConvertToInt() && root.path("version").intValue() == 1
                && kind.equals(text(root, "kind")));
        return root;
    }

    private static Locator locator(JsonNode root) {
        return new Locator(id(root, "correlationId"), id(root, "runId"), id(root, "attemptId"));
    }

    static UUID id(JsonNode root, String field) {
        try {
            String value = text(root, field);
            UUID id = UUID.fromString(value);
            require(id.toString().equals(value));
            uuid(id);
            return id;
        } catch (RuntimeException unavailable) {
            throw new ObservationFailure();
        }
    }

    static long number(JsonNode root, String field) {
        var value = root.path(field);
        require(value.isIntegralNumber() && value.canConvertToLong());
        long number = value.longValue();
        positive(number);
        return number;
    }

    private static Instant timestamp(JsonNode root, String field) {
        String value = text(root, field);
        var parsed = Instant.parse(value);
        require(parsed.toString().equals(value));
        return parsed;
    }

    static String text(JsonNode root, String field) {
        String value = KubernetesSnapshotVerifier.text(root, field);
        require(value.length() <= 256);
        return value;
    }

    static void name(String value, int maximum, boolean dotted) {
        require(value != null && value.length() <= maximum
                && value
                        .matches(dotted
                                ? "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
                                : "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"));
    }

    static void digest(String value) {
        require(value != null && value.matches("sha256:[0-9a-f]{64}"));
    }

    private static void uuid(UUID value) {
        require(value != null && !value.equals(new UUID(0, 0)));
    }

    private static void positive(long value) {
        require(value > 0);
    }

    private static void require(boolean accepted) {
        if (!accepted) {
            throw new ObservationFailure();
        }
    }
}
