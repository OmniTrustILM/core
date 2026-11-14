package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.ai.proxy.FixedCoreHttp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.classic.methods.HttpDelete;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.io.CloseMode;

/** One bounded authenticated API observation/mutation owner; it grants no Core readiness or registration. */
public final class KubernetesApi {
    private static final int MAXIMUM = 1_048_576;
    private static final int TOKEN_MAXIMUM = 8192;
    private static final Set<PosixFilePermission> FORBIDDEN = Set
            .of(PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE,
                    PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                    PosixFilePermission.OWNER_EXECUTE);
    private final CoreEndpoint endpoint;
    private final SSLContext trust;
    private final Path tokenFile;
    private final long started;
    private final long budget;
    private volatile boolean failed;
    private volatile boolean cleanupUncertain;
    private volatile boolean mutationOutcomeUnknown;
    private volatile CallOwner quarantined;
    private final AtomicBoolean inFlight = new AtomicBoolean();
    private final AtomicBoolean gateAttempted = new AtomicBoolean();
    private final AtomicBoolean creationAttempted = new AtomicBoolean();
    private final AtomicBoolean deletionAttempted = new AtomicBoolean();

    public KubernetesApi(CoreEndpoint endpoint, SSLContext trust, Path tokenFile, Duration budget) {
        this(endpoint, trust, tokenFile, budget, System.nanoTime());
    }

    KubernetesApi(CoreEndpoint endpoint, SSLContext trust, Path tokenFile, Duration budget, long started) {
        if (endpoint == null || trust == null || tokenFile == null || !tokenFile.isAbsolute()
                || !tokenFile.equals(tokenFile.normalize()) || !endpoint.origin().getRawPath().isEmpty()
                || budget == null || budget.isZero() || budget.isNegative()
                || budget.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new ObservationFailure();
        }
        this.endpoint = endpoint;
        this.trust = trust;
        this.tokenFile = tokenFile;
        this.budget = budget.toNanos();
        this.started = started;
    }

    public byte[] namespace(String name) {
        return get("/api/v1/namespaces/" + segment(name, 63));
    }

    public byte[] serviceAccount(String namespace, String name) {
        return get(namespaced(namespace) + "/serviceaccounts/" + segment(name, 253));
    }

    public byte[] pod(String namespace, String name) {
        return get(namespaced(namespace) + "/pods/" + segment(name, 253));
    }

    public byte[] pods(String namespace) {
        return get(namespaced(namespace) + "/pods");
    }

    public byte[] job(String namespace, String name) {
        return get("/apis/batch/v1/namespaces/" + segment(namespace, 63) + "/jobs/" + segment(name, 63));
    }

    public byte[] runtimeClass(String name) {
        return get("/apis/node.k8s.io/v1/runtimeclasses/" + segment(name, 253));
    }

    public byte[] configMap(String namespace, String name) {
        return get(namespaced(namespace) + "/configmaps/" + segment(name, 253));
    }

    public record CreatedJob(String uid, String resourceVersion) {
    }

    public CreatedJob createJob(String namespace, String name, byte[] acceptedJob) {
        if (!creationAttempted.compareAndSet(false, true)) {
            failed = true;
            throw new ObservationFailure();
        }
        try {
            String route = "/apis/batch/v1/namespaces/" + segment(namespace, 63) + "/jobs";
            segment(name, 63);
            var job = KubernetesSnapshotVerifier.parse(acceptedJob);
            var metadata = job.path("metadata");
            if (job.size() != 4 || !"batch/v1".equals(job.path("apiVersion").asText())
                    || !"Job".equals(job.path("kind").asText()) || !job.path("spec").isObject() || !metadata.isObject()
                    || !name.equals(KubernetesSnapshotVerifier.text(metadata, "name"))
                    || !namespace.equals(KubernetesSnapshotVerifier.text(metadata, "namespace"))) {
                throw new ObservationFailure();
            }
            var fields = metadata.fieldNames();
            while (fields.hasNext()) {
                if (!Set.of("name", "namespace", "labels", "annotations").contains(fields.next())) {
                    throw new ObservationFailure();
                }
            }
            for (String field : Set.of("labels", "annotations")) {
                if (metadata.has(field) && !metadata.path(field).isObject()) {
                    throw new ObservationFailure();
                }
            }
            var request = new HttpPost(uri(route));
            request
                    .setEntity(new InputStreamEntity(new ByteArrayInputStream(acceptedJob), acceptedJob.length,
                            ContentType.APPLICATION_JSON));
            mutationOutcomeUnknown = true;
            var actual = KubernetesSnapshotVerifier.parse(call(request, 201));
            var assigned = actual.path("metadata");
            String uid = KubernetesSnapshotVerifier.text(assigned, "uid");
            String revision = KubernetesSnapshotVerifier.text(assigned, "resourceVersion");
            UUID parsed = UUID.fromString(uid);
            if (!"batch/v1".equals(actual.path("apiVersion").asText()) || !"Job".equals(actual.path("kind").asText())
                    || !name.equals(assigned.path("name").asText())
                    || !namespace.equals(assigned.path("namespace").asText()) || !parsed.toString().equals(uid)
                    || parsed.equals(new UUID(0, 0)) || !revision.matches("[A-Za-z0-9._:-]{1,128}")
                    || assigned.hasNonNull("deletionTimestamp") || !actual.path("spec").isObject()
                    || cleanupUncertain()) {
                throw new ObservationFailure();
            }
            remaining();
            mutationOutcomeUnknown = false;
            return new CreatedJob(uid, revision);
        } catch (Throwable unavailable) {
            failed = true;
            throw new ObservationFailure();
        }
    }

    public byte[] releaseGate(String namespace, String pod, String uid, String resourceVersion, String gate) {
        if (!gateAttempted.compareAndSet(false, true)) {
            failed = true;
            throw new ObservationFailure();
        }
        try {
            if (!UUID.fromString(uid).toString().equals(uid) || resourceVersion == null
                    || !resourceVersion.matches("[A-Za-z0-9._:-]{1,128}") || gate == null
                    || !gate.matches("[a-z0-9.-]+/[A-Za-z0-9._-]+") || gate.length() > 316) {
                throw new ObservationFailure();
            }
            byte[] body = new ObjectMapper()
                    .writeValueAsBytes(List
                            .of(Map.of("op", "test", "path", "/metadata/uid", "value", uid),
                                    Map.of("op", "test", "path", "/metadata/resourceVersion", "value", resourceVersion),
                                    Map.of("op", "test", "path", "/spec/schedulingGates/0/name", "value", gate),
                                    Map.of("op", "remove", "path", "/spec/schedulingGates/0")));
            var request = new HttpPatch(uri(namespaced(namespace) + "/pods/" + segment(pod, 253)));
            request
                    .setEntity(new InputStreamEntity(new ByteArrayInputStream(body), body.length,
                            ContentType.create("application/json-patch+json")));
            mutationOutcomeUnknown = true;
            byte[] reply = call(request);
            var actual = KubernetesSnapshotVerifier.parse(reply);
            var metadata = actual.path("metadata");
            var gates = actual.path("spec").path("schedulingGates");
            if (!"v1".equals(actual.path("apiVersion").asText()) || !"Pod".equals(actual.path("kind").asText())
                    || !uid.equals(metadata.path("uid").asText())
                    || !namespace.equals(metadata.path("namespace").asText())
                    || !pod.equals(metadata.path("name").asText()) || metadata.hasNonNull("deletionTimestamp")
                    || !metadata.path("resourceVersion").isTextual()
                    || !metadata.path("resourceVersion").textValue().matches("[A-Za-z0-9._:-]{1,128}")
                    || resourceVersion.equals(metadata.path("resourceVersion").textValue())
                    || !actual.path("spec").isObject()
                    || !gates.isMissingNode() && (!gates.isArray() || !gates.isEmpty())) {
                throw new ObservationFailure();
            }
            remaining();
            mutationOutcomeUnknown = false;
            return reply;
        } catch (Throwable unavailable) {
            failed = true;
            throw new ObservationFailure();
        }
    }

    public void deleteJob(String namespace, String name, String uid, String resourceVersion) {
        if (!deletionAttempted.compareAndSet(false, true)) {
            failed = true;
            throw new ObservationFailure();
        }
        try {
            requireUid(uid);
            if (resourceVersion == null || !resourceVersion.matches("[A-Za-z0-9._:-]{1,128}")) {
                throw new ObservationFailure();
            }
            byte[] bytes = new ObjectMapper()
                    .writeValueAsBytes(Map
                            .of("apiVersion", "v1", "kind", "DeleteOptions", "propagationPolicy", "Foreground",
                                    "preconditions", Map.of("uid", uid, "resourceVersion", resourceVersion)));
            var request = new HttpDelete(uri(jobPath(namespace, name)));
            request
                    .setEntity(new InputStreamEntity(new ByteArrayInputStream(bytes), bytes.length,
                            ContentType.APPLICATION_JSON));
            mutationOutcomeUnknown = true;
            var reply = KubernetesSnapshotVerifier.parse(exchange(request, Set.of(200, 202)).body());
            if ("Status".equals(reply.path("kind").asText())) {
                var details = reply.path("details");
                if (!"v1".equals(reply.path("apiVersion").asText()) || !"Success".equals(reply.path("status").asText())
                        || !uid.equals(details.path("uid").asText()) || !name.equals(details.path("name").asText())
                        || !"jobs".equals(details.path("kind").asText())
                        || !"batch".equals(details.path("group").asText())) {
                    throw new ObservationFailure();
                }
            } else if (!"batch/v1".equals(reply.path("apiVersion").asText())
                    || !"Job".equals(reply.path("kind").asText())
                    || !uid.equals(reply.path("metadata").path("uid").asText())
                    || !name.equals(reply.path("metadata").path("name").asText())
                    || !namespace.equals(reply.path("metadata").path("namespace").asText())
                    || !reply.path("metadata").hasNonNull("deletionTimestamp")) {
                throw new ObservationFailure();
            }
            remaining();
            if (cleanupUncertain()) {
                throw new ObservationFailure();
            }
            mutationOutcomeUnknown = false;
        } catch (Throwable unavailable) {
            failed = true;
            throw new ObservationFailure();
        }
    }

    public boolean jobAbsent(String namespace, String name, String uid) {
        requireUid(uid);
        var reply = exchange(new HttpGet(uri(jobPath(namespace, name))), Set.of(200, 404));
        var actual = KubernetesSnapshotVerifier.parse(reply.body());
        if (reply.status() == 200) {
            if (!"batch/v1".equals(actual.path("apiVersion").asText()) || !"Job".equals(actual.path("kind").asText())
                    || !uid.equals(actual.path("metadata").path("uid").asText())
                    || !name.equals(actual.path("metadata").path("name").asText())
                    || !namespace.equals(actual.path("metadata").path("namespace").asText())) {
                throw new ObservationFailure();
            }
            return false;
        }
        var details = actual.path("details");
        if (!"v1".equals(actual.path("apiVersion").asText()) || !"Status".equals(actual.path("kind").asText())
                || !"NotFound".equals(actual.path("reason").asText()) || !actual.path("code").isIntegralNumber()
                || !actual.path("code").canConvertToInt() || actual.path("code").intValue() != 404
                || !name.equals(details.path("name").asText()) || !"batch".equals(details.path("group").asText())
                || !"jobs".equals(details.path("kind").asText())) {
            throw new ObservationFailure();
        }
        remaining();
        return true;
    }

    private static void requireUid(String uid) {
        try {
            UUID parsed = UUID.fromString(uid);
            if (!parsed.toString().equals(uid) || parsed.equals(new UUID(0, 0))) {
                throw new ObservationFailure();
            }
        } catch (RuntimeException invalid) {
            throw new ObservationFailure();
        }
    }

    private static String jobPath(String namespace, String name) {
        return "/apis/batch/v1/namespaces/" + segment(namespace, 63) + "/jobs/" + segment(name, 63);
    }

    private byte[] get(String path) {
        return call(new HttpGet(uri(path)));
    }

    private byte[] call(HttpUriRequestBase request) {
        return call(request, 200);
    }

    private byte[] call(HttpUriRequestBase request, int expectedStatus) {
        return exchange(request, Set.of(expectedStatus)).body();
    }

    private record ApiReply(int status, byte[] body) {
    }

    private ApiReply exchange(HttpUriRequestBase request, Set<Integer> expectedStatus) {
        if (!inFlight.compareAndSet(false, true)) {
            failed = true;
            throw new ObservationFailure();
        }
        try {
            remaining();
            request.setVersion(HttpVersion.HTTP_1_1);
            request.setHeader("Connection", "close");
            request.setHeader("Accept", "application/json");
            request.setHeader("Cache-Control", "no-store");
            request.setHeader("Authorization", "Bearer " + token());
            try (var owner = new CallOwner(request)) {
                remaining();
                var response = CloseableHttpResponse.adapt(owner.client.executeOpen(null, request, null));
                try {
                    if (!expectedStatus.contains(response.getCode())
                            || !HttpVersion.HTTP_1_1.equals(response.getVersion())
                            || response.containsHeader("Content-Encoding") || response.containsHeader("Set-Cookie")
                            || response.containsHeader("Set-Cookie2") || response.getHeaders("Content-Type").length != 1
                            || response.getEntity() == null || response.getEntity().getContentLength() > MAXIMUM) {
                        throw new ObservationFailure();
                    }
                    String type = response.getFirstHeader("Content-Type").getValue();
                    if (type == null || !type
                            .matches(
                                    "(?i)application/json[ \\t]*+(?:;[ \\t]*+charset[ \\t]*+=[ \\t]*+(?:utf-8|\"utf-8\"))?[ \\t]*+")) {
                        throw new ObservationFailure();
                    }
                    var output = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    var input = response.getEntity().getContent();
                    while (true) {
                        remaining();
                        int count = input.read(buffer, 0, Math.min(buffer.length, MAXIMUM + 1 - output.size()));
                        remaining();
                        if (count < 0) {
                            return new ApiReply(response.getCode(), output.toByteArray());
                        }
                        output.write(buffer, 0, count);
                        if (output.size() > MAXIMUM) {
                            throw new ObservationFailure();
                        }
                    }
                } finally {
                    request.cancel();
                    response.close(CloseMode.IMMEDIATE);
                }
            }
        } catch (Throwable unavailable) {
            failed = true;
            throw new ObservationFailure();
        } finally {
            try {
                request.cancel();
            } catch (Throwable cleanup) {
                cleanupUncertain = true;
                failed = true;
            } finally {
                if (!cleanupUncertain()) {
                    inFlight.set(false);
                }
            }
        }
    }

    /** A cleanup uncertainty is a denial signal; callers must not start another owner in its place. */
    public boolean cleanupUncertain() {
        return cleanupUncertain || quarantined != null;
    }

    /** Local I/O closure does not resolve a possible remote mutation; an unknown mutation must not be replayed. */
    public boolean mutationOutcomeUnknown() {
        return mutationOutcomeUnknown;
    }

    private final class CallOwner implements AutoCloseable {
        private final HttpUriRequestBase request;
        private final CloseableHttpClient client;
        private final ScheduledExecutorService guard = Executors.newSingleThreadScheduledExecutor(action -> {
            var thread = new Thread(action, "ai-controller-http-budget");
            thread.setDaemon(true);
            return thread;
        });

        private CallOwner(HttpUriRequestBase request) {
            this.request = request;
            client = FixedCoreHttp.openKubernetes(endpoint, trust, remaining().toNanos());
            try {
                guard.schedule(() -> {
                    failed = true;
                    stopHandles();
                }, remaining().toNanos(), TimeUnit.NANOSECONDS);
            } catch (Throwable unavailable) {
                failed = true;
                close();
                throw new ObservationFailure();
            }
        }

        private void stopHandles() {
            try {
                request.cancel();
            } catch (Throwable cleanup) {
                uncertain();
            }
            try {
                client.close(CloseMode.IMMEDIATE);
            } catch (Throwable cleanup) {
                uncertain();
            }
        }

        private void uncertain() {
            cleanupUncertain = true;
            failed = true;
            quarantined = this;
        }

        @Override
        public void close() {
            try {
                guard.shutdownNow();
            } catch (Throwable cleanup) {
                uncertain();
            }
            stopHandles();
            try {
                if (!guard.awaitTermination(1, TimeUnit.SECONDS)) {
                    uncertain();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                uncertain();
            }
            if (failed || cleanupUncertain) {
                throw new ObservationFailure();
            }
        }
    }

    private String token() throws Exception {
        remaining();
        Path resolved = tokenFile.toRealPath();
        var before = Files.readAttributes(resolved, BasicFileAttributes.class);
        privateFile(resolved, before);
        byte[] bytes = new byte[TOKEN_MAXIMUM + 1];
        try {
            var buffer = ByteBuffer.wrap(bytes);
            try (var channel = Files.newByteChannel(resolved)) {
                while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                    remaining();
                }
            }
            var after = Files.readAttributes(resolved, BasicFileAttributes.class);
            privateFile(resolved, after);
            if (!resolved.equals(tokenFile.toRealPath()) || !Objects.equals(before.fileKey(), after.fileKey())
                    || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || buffer.position() != before.size()) {
                throw new ObservationFailure();
            }
            String value = new String(bytes, 0, buffer.position(), StandardCharsets.US_ASCII);
            if (!value.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) {
                throw new ObservationFailure();
            }
            return value;
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void privateFile(Path path, BasicFileAttributes attributes) throws Exception {
        if (!attributes.isRegularFile() || attributes.fileKey() == null || attributes.size() <= 0
                || attributes.size() > TOKEN_MAXIMUM
                || Files.getPosixFilePermissions(path).stream().anyMatch(FORBIDDEN::contains)) {
            throw new ObservationFailure();
        }
    }

    Duration remaining() {
        long elapsed = System.nanoTime() - started;
        if (failed || elapsed < 0 || elapsed >= budget) {
            failed = true;
            throw new ObservationFailure();
        }
        return Duration.ofNanos(budget - elapsed);
    }

    private URI uri(String path) {
        return URI.create(endpoint.origin().toASCIIString() + path);
    }

    private static String namespaced(String namespace) {
        return "/api/v1/namespaces/" + segment(namespace, 63);
    }

    private static String segment(String value, int maximum) {
        if (value == null || value.length() > maximum || !value.matches("[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?")) {
            throw new ObservationFailure();
        }
        return value;
    }
}
