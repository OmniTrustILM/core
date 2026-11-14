package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.controller.KubernetesApi;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Publishes bounded optimistic API observations, not an atomic cluster snapshot. Revision rollback protection lasts for
 * this publisher's lifetime. Successful reads renew before expiry without enabling business execution.
 */
public final class AiRuntimeNativeMaterialPublisher
        implements
            Supplier<RuntimeProxyTrustManager.Policy>,
            AutoCloseable {
    private static final Logger LOGGER = LoggerFactory.getLogger(AiRuntimeNativeMaterialPublisher.class);
    private static final ObjectMapper JSON = ObjectMapperFactory.aiGatewayWire();
    private static final ObjectMapper KUBERNETES_JSON = ObjectMapperFactory.aiKubernetesWire();
    private static final Duration FRESHNESS = Duration.ofSeconds(30);
    private static final Duration RENEWAL_MARGIN = Duration.ofSeconds(15);
    private static final String METADATA = "metadata";
    private final Source source;
    private final Clock clock;
    private final LongSupplier nanos;
    private final AtomicBoolean refreshing = new AtomicBoolean();
    private volatile Snapshot published;
    private volatile KubernetesApi quarantined;
    private volatile boolean closed;
    private Snapshot accepted;
    private long generation;

    public AiRuntimeNativeMaterialPublisher(Source source, Clock clock) {
        this(source, clock, System::nanoTime);
    }

    AiRuntimeNativeMaterialPublisher(Source source, Clock clock, LongSupplier nanos) {
        this.source = Objects.requireNonNull(source);
        this.clock = Objects.requireNonNull(clock);
        this.nanos = Objects.requireNonNull(nanos);
    }

    public void refresh(AiRuntimeOperationBudget budget) {
        if (!refreshing.compareAndSet(false, true)) {
            invalidate();
            return;
        }
        KubernetesApi api = null;
        try {
            long expectedGeneration;
            synchronized (this) {
                require(!closed && quarantined == null);
                expectedGeneration = generation;
            }
            Instant observedAt = clock.instant();
            long started = nanos.getAsLong();
            api = source.api().open(budget.remaining());
            String namespaceVersion = namespaceVersion(api.namespace(source.namespaceName()));
            JsonNode configMap = json(api.configMap(source.namespaceName(), source.configMapName()));
            String configVersion = identity(configMap, "ConfigMap", source.configMapName(), source.configMapUid(),
                    source.namespaceName());
            require(namespaceVersion.equals(namespaceVersion(api.namespace(source.namespaceName()))));
            require(!api.cleanupUncertain());
            Snapshot candidate = policy(configMap, namespaceVersion, configVersion, observedAt, started);
            publish(candidate, expectedGeneration, budget);
            LOGGER.debug("AI runtime trust policy status=PUBLISHED");
        } catch (Throwable unavailable) {
            invalidate();
            LOGGER.debug("AI runtime trust policy status=UNAVAILABLE");
        } finally {
            if (api != null && api.cleanupUncertain()) {
                synchronized (this) {
                    quarantined = api;
                    invalidate();
                }
            }
            refreshing.set(false);
        }
    }

    @Override
    public RuntimeProxyTrustManager.Policy get() {
        return current().map(PolicySnapshot::policy).orElse(null);
    }

    /** Captures the verified source revision and policy from one still-current publication. */
    public Optional<PolicySnapshot> current() {
        Snapshot snapshot = published;
        return snapshot != null && fresh(snapshot) && !closed && quarantined == null && published == snapshot
                ? Optional.of(new PolicySnapshot(snapshot.revision(), snapshot.policy()))
                : Optional.empty();
    }

    public record PolicySnapshot(long revision, RuntimeProxyTrustManager.Policy policy) {
        public PolicySnapshot {
            require(revision > 0 && policy != null);
        }

        @Override
        public String toString() {
            return "NativePolicySnapshot[revision=" + revision + "]";
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        invalidate();
    }

    private synchronized void invalidate() {
        published = null;
        generation++;
    }

    private synchronized void publish(Snapshot candidate, long expectedGeneration, AiRuntimeOperationBudget budget) {
        require(!closed && quarantined == null && generation == expectedGeneration && fresh(candidate));
        if (accepted != null) {
            boolean sameContent = accepted.content().equals(candidate.content());
            require(candidate.revision() >= accepted.revision());
            require(sameContent || candidate.revision() > accepted.revision());
            require(sameContent || !candidate.configVersion().equals(accepted.configVersion()));
            if (sameContent && published == accepted && accepted.namespaceVersion().equals(candidate.namespaceVersion())
                    && accepted.configVersion().equals(candidate.configVersion()) && reusable(accepted)) {
                candidate = accepted;
            }
        }
        budget.remaining();
        accepted = candidate;
        published = candidate;
    }

    private boolean fresh(Snapshot snapshot) {
        Instant now = clock.instant();
        long elapsed = nanos.getAsLong() - snapshot.started();
        return elapsed >= 0 && elapsed < FRESHNESS.toNanos() && !now.isBefore(snapshot.policy().observedAt())
                && now.isBefore(snapshot.policy().expiresAt());
    }

    private boolean reusable(Snapshot snapshot) {
        return fresh(snapshot) && nanos.getAsLong() - snapshot.started() < FRESHNESS.minus(RENEWAL_MARGIN).toNanos()
                && clock.instant().isBefore(snapshot.policy().expiresAt().minus(RENEWAL_MARGIN));
    }

    private String namespaceVersion(byte[] body) throws Exception {
        return identity(json(body), "Namespace", source.namespaceName(), source.namespaceUid(), null);
    }

    private static String identity(JsonNode object, String kind, String name, UUID uid, String namespace) {
        require(object.isObject() && "v1".equals(object.path("apiVersion").textValue())
                && kind.equals(object.path("kind").textValue()));
        JsonNode metadata = object.path(METADATA);
        require(metadata.isObject() && name.equals(metadata.path("name").textValue())
                && uid.toString().equals(metadata.path("uid").textValue()) && !metadata.hasNonNull("deletionTimestamp")
                && (namespace == null
                        ? !metadata.hasNonNull("namespace")
                        : namespace.equals(metadata.path("namespace").textValue())));
        return text(metadata.path("resourceVersion"), 256);
    }

    private static Snapshot policy(JsonNode configMap, String namespaceVersion, String configVersion, Instant observed,
            long started) throws Exception {
        JsonNode data = configMap.path("data");
        require(data.isObject() && data.size() == 1 && (!configMap.hasNonNull("binaryData")
                || configMap.path("binaryData").isObject() && configMap.path("binaryData").isEmpty()));
        String content = text(data.path("policy.json"), 524288);
        JsonNode body = JSON.readTree(content);
        fields(body, Set.of("version", "revision", "authorities", "deniedTbsFingerprints"));
        require(body.path("version").isIntegralNumber() && body.path("version").canConvertToInt()
                && body.path("version").intValue() == 1);
        JsonNode revision = body.path("revision");
        require(revision.isIntegralNumber() && revision.canConvertToLong() && revision.longValue() > 0);
        var authorities = authorities(body.path("authorities"), observed);
        JsonNode fingerprints = body.path("deniedTbsFingerprints");
        require(fingerprints.isArray() && fingerprints.size() <= 4096);
        Set<String> denied = new HashSet<>();
        for (JsonNode fingerprint : fingerprints) {
            String value = text(fingerprint, 64);
            require(value.matches("[0-9a-f]{64}") && denied.add(value));
        }
        var policy = new RuntimeProxyTrustManager.Policy(authorities, denied, observed, observed.plus(FRESHNESS));
        return new Snapshot(namespaceVersion, configVersion, content, revision.longValue(), policy, started);
    }

    private static List<RuntimeProxyTrustManager.Authority> authorities(JsonNode values, Instant observed)
            throws Exception {
        require(values.isArray() && !values.isEmpty() && values.size() <= 8);
        List<RuntimeProxyTrustManager.Authority> authorities = new ArrayList<>();
        var factory = CertificateFactory.getInstance("X.509", "SUN");
        for (JsonNode value : values) {
            fields(value, Set.of("cluster", "certificateDerBase64"));
            String encoded = text(value.path("certificateDerBase64"), 21848);
            byte[] bytes = Base64.getDecoder().decode(encoded);
            require(bytes.length > 0 && bytes.length <= 16384
                    && Base64.getEncoder().encodeToString(bytes).equals(encoded));
            var input = new ByteArrayInputStream(bytes);
            var certificate = (X509Certificate) factory.generateCertificate(input);
            require(input.available() == 0 && bytes[0] == 0x30 && Arrays.equals(certificate.getEncoded(), bytes)
                    && RuntimeProxyTrustManager.unconstrainedAnchor(certificate));
            certificate.checkValidity(java.util.Date.from(observed));
            boolean[] usage = certificate.getKeyUsage();
            require(usage != null && usage.length > 5 && usage[5]);
            var authority = new RuntimeProxyTrustManager.Authority(text(value.path("cluster"), 63), certificate);
            require(!authorities.contains(authority));
            authorities.add(authority);
        }
        return authorities;
    }

    private static JsonNode json(byte[] bytes) throws Exception {
        require(bytes.length > 0 && bytes.length <= 1048576);
        return KUBERNETES_JSON.readTree(StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString());
    }

    private static void fields(JsonNode object, Set<String> names) {
        require(object != null && object.isObject() && object.size() == names.size());
        object.fieldNames().forEachRemaining(name -> require(names.contains(name)));
    }

    private static String text(JsonNode value, int maximum) {
        require(value.isTextual() && !value.textValue().isBlank() && value.textValue().length() <= maximum);
        return value.textValue();
    }

    private static void require(boolean valid) {
        if (!valid) {
            throw new IllegalArgumentException("Runtime trust material unavailable");
        }
    }

    public record Source(KubernetesConfiguration api, String namespaceName, UUID namespaceUid, String configMapName,
            UUID configMapUid) {
        public Source {
            require(api != null && namespaceName != null && namespaceName.length() <= 63
                    && namespaceName.matches("[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?") && configMapName != null
                    && configMapName.length() <= 253 && configMapName.matches("[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?")
                    && !configMapName.contains("..") && namespaceUid != null && configMapUid != null
                    && !namespaceUid.equals(new UUID(0, 0)) && !configMapUid.equals(new UUID(0, 0)));
        }

        @Override
        public String toString() {
            return "Runtime trust policy source";
        }
    }

    private record Snapshot(String namespaceVersion, String configVersion, String content, long revision,
            RuntimeProxyTrustManager.Policy policy, long started) {
    }
}
