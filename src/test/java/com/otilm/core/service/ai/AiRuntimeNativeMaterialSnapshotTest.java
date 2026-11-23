package com.otilm.core.service.ai;

import com.otilm.core.security.ai.AiRuntimeNativeMaterialPublisher;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

/** Actual policy API parsing/publication and immutable revision capture, not readiness or native acceptance. */
class AiRuntimeNativeMaterialSnapshotTest {
    private static final UUID NAMESPACE = UUID.fromString("77bd9027-9e2a-43b4-890f-a36eb970ae46");
    private static final UUID CONFIG = UUID.fromString("51fd9d23-03ce-4d1c-a4cc-ecf095e381a4");
    @TempDir
    Path directory;

    @Test
    void oneFreshPublicationReturnsItsMatchingImmutablePolicyAndVerifiedSourceRevision() throws Exception {
        try (var fixture = new Fixture(directory); var publisher = fixture.publisher()) {
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.current().orElseThrow();
            assertThat(first.revision()).isEqualTo(7);
            assertThat(first.policy()).isSameAs(publisher.get());
            assertThat(first.policy().observedAt()).isEqualTo(fixture.clock.instant());
            fixture.clock.at.updateAndGet(value -> value.plusSeconds(1));
            fixture.revision.set(8);
            publisher.refresh(AiRuntimeOperationBudget.start());
            var second = publisher.current().orElseThrow();
            assertThat(second.revision()).isEqualTo(8);
            assertThat(second.policy()).isSameAs(publisher.get());
            assertThat(second.policy().observedAt()).isEqualTo(fixture.clock.instant());
            assertThat(first.revision()).isEqualTo(7);
            assertThat(first.policy().observedAt()).isEqualTo(fixture.clock.instant().minusSeconds(1));
            assertThat(fixture.api.requests).hasValue(6);
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void revisionRollbackCannotReturnThePreviouslyAcceptedPolicyAsCurrent() throws Exception {
        try (var fixture = new Fixture(directory); var publisher = fixture.publisher()) {
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current().orElseThrow().revision()).isEqualTo(7);
            fixture.revision.set(6);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current()).isEmpty();
            assertThat(publisher.get()).isNull();
            assertThat(fixture.api.failure.get()).isNull();
        }
    }

    @Test
    void expiryApiFailureAndOwningCloseCannotReturnAFreshRevisionSnapshot() throws Exception {
        try (var fixture = new Fixture(directory); var publisher = fixture.publisher()) {
            assertThat(publisher.current()).isEmpty();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current()).isPresent();
            fixture.clock.at.updateAndGet(value -> value.plusSeconds(30));
            assertThat(publisher.current()).isEmpty();
            fixture.revision.set(8);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current()).isPresent();
            fixture.failed = true;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current()).isEmpty();
            fixture.failed = false;
            fixture.revision.set(9);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.current().orElseThrow().revision()).isEqualTo(9);
            publisher.close();
            assertThat(publisher.current()).isEmpty();
            assertThat(publisher.get()).isNull();
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> at = new AtomicReference<>(Instant.now());

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(instant(), zone);
        }

        @Override
        public Instant instant() {
            return at.get();
        }
    }

    private static final class Fixture implements AutoCloseable {
        private final MutableClock clock = new MutableClock();
        private final AtomicLong revision = new AtomicLong(7);
        private final ControllerServiceApiFixture api;
        private volatile boolean failed;

        private Fixture(Path directory) throws Exception {
            api = new ControllerServiceApiFixture(directory);
            String root = Base64.getEncoder().encodeToString(Files.readAllBytes(api.configuration().serverCaFile()));
            api.responder = path -> {
                try {
                    var json = ObjectMapperFactory.aiKubernetesWire();
                    if (failed) {
                        return new ControllerServiceApiFixture.Reply(503, new byte[]{'{', '}'});
                    }
                    var body = json.createObjectNode().put("apiVersion", "v1");
                    if (path.equals("/api/v1/namespaces/runtime")) {
                        body.put("kind", "Namespace");
                        body
                                .putObject("metadata")
                                .put("name", "runtime")
                                .put("uid", NAMESPACE.toString())
                                .put("resourceVersion", "namespace-rv");
                    } else if (path.equals("/api/v1/namespaces/runtime/configmaps/policy")) {
                        body.put("kind", "ConfigMap");
                        body
                                .putObject("metadata")
                                .put("name", "policy")
                                .put("namespace", "runtime")
                                .put("uid", CONFIG.toString())
                                .put("resourceVersion", "policy-rv-" + revision.get());
                        var policy = json.createObjectNode().put("version", 1).put("revision", revision.get());
                        policy
                                .putArray("authorities")
                                .addObject()
                                .put("cluster", "lab")
                                .put("certificateDerBase64", root);
                        policy.putArray("deniedTbsFingerprints");
                        body.putObject("data").put("policy.json", json.writeValueAsString(policy));
                    } else {
                        throw new AssertionError("Unexpected synthetic policy source path");
                    }
                    return new ControllerServiceApiFixture.Reply(200, json.writeValueAsBytes(body));
                } catch (Exception invalid) {
                    throw new AssertionError(invalid);
                }
            };
        }

        private AiRuntimeNativeMaterialPublisher publisher() {
            return new AiRuntimeNativeMaterialPublisher(new AiRuntimeNativeMaterialPublisher.Source(api.configuration(),
                    "runtime", NAMESPACE, "policy", CONFIG), clock);
        }

        @Override
        public void close() throws Exception {
            api.close();
        }
    }
}
