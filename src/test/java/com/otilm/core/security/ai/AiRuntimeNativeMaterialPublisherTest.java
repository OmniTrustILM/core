package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeNativeMaterialPublisherTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID NAMESPACE_UID = UUID.fromString("2ac41ef2-5163-4ef7-9a21-c2d71b7712b2");
    private static final UUID CONFIG_UID = UUID.fromString("49b6a1d2-bce9-46db-9d78-e30d57cec64b");
    private static final String NAMESPACE_PATH = "/api/v1/namespaces/runtime";
    private static final String POLICY_PATH = NAMESPACE_PATH + "/configmaps/runtime-trust";
    @TempDir
    Path directory;

    @Test
    void onlyAuthenticatedUidBoundApiReadsPublishFreshStablePolicyWithoutDoingIoInGet() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            assertThat(publisher.get()).isNull();
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.get();
            assertThat(first).isNotNull();
            assertThat(first.authorities()).hasSize(1);
            assertThat(first.authorities().getFirst().cluster()).isEqualTo("lab");
            assertThat(first.authorities().getFirst().certificate()).isEqualTo(api.authority.certificate());
            assertThat(first.deniedTbsFingerprints()).containsExactly("1".repeat(64));
            assertThat(first.observedAt()).isEqualTo(api.clock.instant());
            assertThat(first.expiresAt()).isEqualTo(api.clock.instant().plusSeconds(30));
            assertThat(api.paths).containsExactly(NAMESPACE_PATH, POLICY_PATH, NAMESPACE_PATH);
            int requests = api.requests.get();
            assertThat(publisher.get()).isSameAs(first);
            assertThat(api.requests).hasValue(requests);
            api.clock.advance(Duration.ofSeconds(4));
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isSameAs(first);
            assertThat(api.requests).hasValue(requests + 3);
            assertThat(api.paths)
                    .containsExactly(NAMESPACE_PATH, POLICY_PATH, NAMESPACE_PATH, NAMESPACE_PATH, POLICY_PATH,
                            NAMESPACE_PATH);
            assertThat(api.methods).hasValue(0);
        }
    }

    @Test
    void expiryClockRollbackAndHttpFailureRemoveAccessUntilAnotherSuccessfulApiRead() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.get();
            api.clock.advance(Duration.ofSeconds(30));
            assertThat(publisher.get()).isNull();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull().isNotSameAs(first);
            api.clock.advance(Duration.ofSeconds(-1));
            assertThat(publisher.get()).isNull();
            api.clock.advance(Duration.ofSeconds(1));
            api.status = 503;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.status = 200;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void successfulRecoveryCannotRestoreTheSnapshotThatAnInterveningFailureInvalidated() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            var beforeFailure = publisher.get();
            assertThat(beforeFailure).isNotNull();
            api.clock.advance(Duration.ofSeconds(1));
            api.status = 503;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.status = 200;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull().isNotSameAs(beforeFailure);
            assertThat(publisher.get().observedAt()).isAfter(beforeFailure.observedAt());
        }
    }

    @Test
    void successfulReadsRenewBeforeExpiryAndThenKeepTheNewSnapshotStable() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.get();
            api.clock.advance(Duration.ofSeconds(16));
            publisher.refresh(AiRuntimeOperationBudget.start());
            var renewed = publisher.get();
            assertThat(renewed).isNotNull().isNotSameAs(first);
            assertThat(renewed.observedAt()).isEqualTo(api.clock.instant());
            api.clock.advance(Duration.ofSeconds(4));
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isSameAs(renewed);
        }
    }

    @Test
    void successfulReadsAlsoRenewWithAFrozenWallClockWhenMonotonicHeadroomShrinks() throws Exception {
        try (var api = new Api(directory)) {
            var nanos = new java.util.concurrent.atomic.AtomicLong();
            var publisher = new AiRuntimeNativeMaterialPublisher(api.source(), api.clock, nanos::get);
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.get();
            nanos.addAndGet(Duration.ofSeconds(16).toNanos());
            publisher.refresh(AiRuntimeOperationBudget.start());
            var renewed = publisher.get();
            assertThat(renewed).isNotNull().isNotSameAs(first);
            nanos.addAndGet(Duration.ofSeconds(4).toNanos());
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isSameAs(renewed);
        }
    }

    @Test
    void aFrozenWallClockCannotExtendMonotonicFreshnessOrAuthorizeAfterMonotonicRollback() throws Exception {
        try (var api = new Api(directory)) {
            var nanos = new java.util.concurrent.atomic.AtomicLong(100);
            var publisher = new AiRuntimeNativeMaterialPublisher(api.source(), api.clock, nanos::get);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            nanos.addAndGet(Duration.ofSeconds(30).toNanos());
            assertThat(publisher.get()).isNull();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            nanos.decrementAndGet();
            assertThat(publisher.get()).isNull();
        }
    }

    @Test
    void exactDerAuthoritiesRejectBase64OfPemTextAndTrailingDerData() throws Exception {
        try (var api = new Api(directory)) {
            byte[] der = api.authority.certificate().getEncoded();
            String pem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der) + "\n-----END CERTIFICATE-----";
            for (byte[] invalid : List
                    .of(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            java.util.Arrays.copyOf(der, der.length + 1))) {
                ((ObjectNode) api.policy.path("authorities").get(0))
                        .put("certificateDerBase64", Base64.getEncoder().encodeToString(invalid));
                api.publishPolicy("11");
                var publisher = api.publisher();
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNull();
            }
        }
    }

    @Test
    void validLongKubernetesAnnotationNamesDoNotBlockTheSeparatelyStrictPolicySchema() throws Exception {
        try (var api = new Api(directory)) {
            String annotation = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61)
                    + "/" + "n".repeat(63);
            ((ObjectNode) api.namespace.path("metadata")).putObject("annotations").put(annotation, "synthetic");
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void changedPolicyMustAdvanceRevisionAndResourceVersionAndCannotRollBackAfterFailure() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            var first = publisher.get();
            api.policy.put("revision", 2);
            api.publishPolicy("12");
            publisher.refresh(AiRuntimeOperationBudget.start());
            var second = publisher.get();
            assertThat(second).isNotNull().isNotSameAs(first);
            api.policy.putArray("deniedTbsFingerprints").add("2".repeat(64));
            api.publishPolicy("13");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.policy.put("revision", 1);
            api.publishPolicy("14");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.policy.put("revision", 3);
            api.publishPolicy("12");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.publishPolicy("15");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get().deniedTbsFingerprints()).containsExactly("2".repeat(64));
        }
    }

    @Test
    void wrongNamespaceOrConfigMapIdentityNeverPublishesEvenAfterPreviouslyTrustedRead() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            for (String field : List.of("uid", "name", "deletionTimestamp")) {
                ObjectNode original = api.namespace.deepCopy();
                ((ObjectNode) api.namespace.get("metadata")).put(field, "00000000-0000-0000-0000-000000000000");
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("namespace %s", field).isNull();
                api.namespace = original;
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
            }
            for (String field : List.of("uid", "name", "namespace", "resourceVersion", "deletionTimestamp")) {
                ObjectNode original = api.configMap.deepCopy();
                ((ObjectNode) api.configMap.get("metadata")).put(field, "");
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("configMap %s", field).isNull();
                api.configMap = original;
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
            }
            for (String field : List.of("kind", "apiVersion")) {
                ObjectNode originalNamespace = api.namespace.deepCopy();
                api.namespace.put(field, "wrong");
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("namespace %s", field).isNull();
                api.namespace = originalNamespace;
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
                ObjectNode original = api.configMap.deepCopy();
                api.configMap.put(field, "wrong");
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("configMap %s", field).isNull();
                api.configMap = original;
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
            }
        }
    }

    @Test
    void policySchemaRejectsUnknownFieldsDuplicatesMalformedCertificatesAndInvalidBounds() throws Exception {
        try (var api = new Api(directory)) {
            String valid = api.policy.toString();
            List<String> invalid = List
                    .of("{}", valid + " {}", valid.replace("\"version\":1", "\"version\":2"),
                            valid.replace("\"version\":1", "\"version\":4294967297"),
                            valid.replace("\"revision\":1", "\"revision\":0"),
                            valid.replace("\"revision\":1", "\"revision\":1.0"),
                            valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
                            valid.replace("\"version\":1", "\"version\":1,\"extra\":true"),
                            valid.replace("\"cluster\":\"lab\"", "\"cluster\":\"BAD_CLUSTER\""),
                            valid
                                    .replace(Base64
                                            .getEncoder()
                                            .encodeToString(api.authority.certificate().getEncoded()), "AA=="),
                            valid.replace("1".repeat(64), "short"),
                            valid.replace("\"authorities\":[", "\"authorities\":[] ,\"unused\":["));
            for (String text : invalid) {
                var publisher = api.publisher();
                ((ObjectNode) api.configMap.get("data")).put("policy.json", text);
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("closed policy schema").isNull();
            }
        }
    }

    @Test
    void closeDuringAnActualReadPreventsItsLaterPublicationAndEveryFurtherRefresh() throws Exception {
        try (var api = new Api(directory); var worker = Executors.newSingleThreadExecutor()) {
            var publisher = api.publisher();
            api.block = true;
            var refresh = worker.submit(() -> publisher.refresh(AiRuntimeOperationBudget.start()));
            assertThat(api.entered.await(3, TimeUnit.SECONDS)).isTrue();
            publisher.close();
            api.release.countDown();
            refresh.get(5, TimeUnit.SECONDS);
            assertThat(publisher.get()).isNull();
            int requests = api.requests.get();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(api.requests).hasValue(requests);
        }
    }

    @Test
    void competingRefreshInvalidatesTheInFlightPublicationInsteadOfStartingAnotherOwner() throws Exception {
        try (var api = new Api(directory); var worker = Executors.newSingleThreadExecutor()) {
            var publisher = api.publisher();
            api.block = true;
            var refresh = worker.submit(() -> publisher.refresh(AiRuntimeOperationBudget.start()));
            assertThat(api.entered.await(3, TimeUnit.SECONDS)).isTrue();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(api.requests).hasValue(1);
            api.release.countDown();
            refresh.get(5, TimeUnit.SECONDS);
            assertThat(publisher.get()).isNull();
            api.block = false;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void exhaustedOperationBudgetCannotReadOrKeepAnEarlierCachedPolicy() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            int requests = api.requests.get();
            var budget = AiRuntimeOperationBudget.start(Duration.ofNanos(1));
            publisher.refresh(budget);
            assertThat(publisher.get()).isNull();
            assertThat(api.requests).hasValue(requests);
        }
    }

    @Test
    void administratorSourceMustContainFixedNamesAndNonzeroObjectIdentities() throws Exception {
        try (var api = new Api(directory)) {
            var configuration = api.configuration();
            for (String name : List.of("", "Runtime", "../runtime", "x".repeat(64))) {
                assertThatThrownBy(() -> new AiRuntimeNativeMaterialPublisher.Source(configuration, name, NAMESPACE_UID,
                        "runtime-trust", CONFIG_UID)).isInstanceOf(IllegalArgumentException.class);
            }
            for (String name : List.of("", "Trust", "../runtime-trust", "x..y", "x".repeat(254))) {
                assertThatThrownBy(() -> new AiRuntimeNativeMaterialPublisher.Source(configuration, "runtime",
                        NAMESPACE_UID, name, CONFIG_UID)).isInstanceOf(IllegalArgumentException.class);
            }
            assertThatThrownBy(() -> new AiRuntimeNativeMaterialPublisher.Source(null, "runtime", NAMESPACE_UID,
                    "runtime-trust", CONFIG_UID)).isInstanceOf(IllegalArgumentException.class);
            for (UUID uid : new UUID[]{null, new UUID(0, 0)}) {
                assertThatThrownBy(() -> new AiRuntimeNativeMaterialPublisher.Source(configuration, "runtime", uid,
                        "runtime-trust", CONFIG_UID)).isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> new AiRuntimeNativeMaterialPublisher.Source(configuration, "runtime",
                        NAMESPACE_UID, "runtime-trust", uid)).isInstanceOf(IllegalArgumentException.class);
            }
            assertThat(api.requests).hasValue(0);
        }
    }

    @Test
    void namespaceRecreatedOrChangedDuringTheConfigMapReadCannotPublishTheEarlierObservation() throws Exception {
        try (var api = new Api(directory)) {
            for (String field : List.of("uid", "resourceVersion")) {
                api.namespaceReads.set(0);
                api.laterNamespace = api.namespace.deepCopy();
                ((ObjectNode) api.laterNamespace.get("metadata"))
                        .put(field, field.equals("uid") ? "c73a9206-c97c-42c9-b5ed-fcbf4af47cbb" : "2");
                var publisher = api.publisher();
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).as("namespace changed %s", field).isNull();
            }
            api.laterNamespace = null;
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void stalledApiResponseIsCutOffAndCannotRetainAnEarlierPolicy() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            api.block = true;
            long started = System.nanoTime();
            publisher.refresh(AiRuntimeOperationBudget.start(Duration.ofMillis(400)));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
            assertThat(api.entered.getCount()).isZero();
            assertThat(publisher.get()).isNull();
            api.block = false;
            api.release.countDown();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void emptyRepeatedOrOversizedAuthorityAndRevocationSetsFailClosed() throws Exception {
        try (var api = new Api(directory)) {
            ObjectNode valid = api.policy.deepCopy();
            for (int size : new int[]{0, 2, 9}) {
                ObjectNode policy = valid.deepCopy();
                var authorities = policy.putArray("authorities");
                for (int index = 0; index < size; index++) {
                    authorities.add(valid.path("authorities").get(0).deepCopy());
                }
                ((ObjectNode) api.configMap.get("data")).put("policy.json", policy.toString());
                var publisher = api.publisher();
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNull();
            }
            ObjectNode policy = valid.deepCopy();
            var fingerprints = policy.putArray("deniedTbsFingerprints");
            fingerprints.add("1".repeat(64)).add("1".repeat(64));
            ((ObjectNode) api.configMap.get("data")).put("policy.json", policy.toString());
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            fingerprints.removeAll();
            for (int index = 0; index < 4097; index++) {
                fingerprints.add(String.format("%064x", index));
            }
            ((ObjectNode) api.configMap.get("data")).put("policy.json", policy.toString());
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
        }
    }

    @Test
    void maximumAuthorityAndRevocationBoundsAcceptTheirExactLimits() throws Exception {
        try (var api = new Api(directory)) {
            var authority = api.policy.path("authorities").get(0).deepCopy();
            var authorities = api.policy.putArray("authorities");
            for (int index = 0; index < 8; index++) {
                var value = authority.deepCopy();
                ((ObjectNode) value).put("cluster", "cluster-" + index);
                authorities.add(value);
            }
            var fingerprints = api.policy.putArray("deniedTbsFingerprints");
            for (int index = 0; index < 4096; index++) {
                fingerprints.add(String.format("%064x", index));
            }
            api.publishPolicy("11");
            var publisher = api.publisher();
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
            assertThat(publisher.get().authorities()).hasSize(8);
            assertThat(publisher.get().deniedTbsFingerprints()).hasSize(4096);
        }
    }

    @Test
    void invalidTypedPolicyFieldsDenyWithoutBreakingTheValidControl() throws Exception {
        try (var api = new Api(directory)) {
            String valid = api.policy.toString();
            ObjectNode invalidEncoding = api.policy.deepCopy();
            ((ObjectNode) invalidEncoding.path("authorities").get(0))
                    .put("certificateDerBase64",
                            Base64.getEncoder().encodeToString(api.authority.certificate().getEncoded()) + "\n");
            List<String> invalid = List
                    .of(valid.replace("\"revision\":1", "\"revision\":-1"),
                            valid.replace("\"revision\":1", "\"revision\":\"1\""),
                            valid.replace("\"revision\":1", "\"revision\":9223372036854775808"),
                            valid.replace("1".repeat(64), "A".repeat(64)), invalidEncoding.toString());
            for (String content : invalid) {
                ((ObjectNode) api.configMap.get("data")).put("policy.json", content);
                var publisher = api.publisher();
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNull();
                ((ObjectNode) api.configMap.get("data")).put("policy.json", valid);
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
            }
        }
    }

    @Test
    void configurationExtrasAndInvalidUtf8CannotHideBehindAValidPolicy() throws Exception {
        try (var api = new Api(directory)) {
            var publisher = api.publisher();
            ((ObjectNode) api.configMap.get("data")).put("other.json", "synthetic");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            ((ObjectNode) api.configMap.get("data")).remove("other.json");
            api.configMap.putObject("binaryData").put("other", "AA==");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.configMap.remove("binaryData");
            ((ObjectNode) api.namespace.get("metadata")).put("namespace", "runtime");
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            ((ObjectNode) api.namespace.get("metadata")).remove("namespace");
            api.rawNamespace = new byte[]{(byte) 0xff};
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            api.rawNamespace = null;
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNotNull();
        }
    }

    @Test
    void expiredFutureAndNonSigningAuthoritiesCannotPublish() throws Exception {
        try (var api = new Api(directory)) {
            Instant now = api.clock.instant();
            var expired = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(20),
                    now.minusSeconds(1));
            var future = issue(null, true, KeyUsage.keyCertSign, null, null, now.plusSeconds(1), now.plusSeconds(20));
            var nonSigning = issue(null, true, KeyUsage.digitalSignature, null, null, now.minusSeconds(20),
                    now.plusSeconds(20));
            var builder = RuntimeProxyTrustManagerTest
                    .builder(null, api.authority.keys(), true, KeyUsage.keyCertSign, null, null, now.minusSeconds(20),
                            now.plusSeconds(20));
            builder
                    .replaceExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                            new org.bouncycastle.asn1.x509.BasicConstraints(0));
            var constrainedCertificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .getCertificate(builder
                            .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                                    .build(api.authority.keys().getPrivate())));
            var constrained = new RuntimeProxyTrustManagerTest.Identity(api.authority.keys(), constrainedCertificate);
            String original = api.policy.toString();
            for (var invalid : List.of(expired, future, nonSigning, constrained)) {
                ((ObjectNode) api.policy.path("authorities").get(0))
                        .put("certificateDerBase64",
                                Base64.getEncoder().encodeToString(invalid.certificate().getEncoded()));
                api.publishPolicy("11");
                var publisher = api.publisher();
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNull();
                ((ObjectNode) api.configMap.get("data")).put("policy.json", original);
                publisher.refresh(AiRuntimeOperationBudget.start());
                assertThat(publisher.get()).isNotNull();
            }
        }
    }

    @Test
    void uncertainApiCleanupPermanentlyRetainsTheOwnerInsteadOfOpeningAnother() throws Exception {
        try (var api = new Api(directory)) {
            var configuration = org.mockito.Mockito.mock(KubernetesConfiguration.class);
            var client = org.mockito.Mockito.mock(com.otilm.ai.controller.KubernetesApi.class);
            var opens = new AtomicInteger();
            var uncertain = new java.util.concurrent.atomic.AtomicBoolean(true);
            org.mockito.Mockito
                    .when(configuration.open(org.mockito.ArgumentMatchers.any(Duration.class)))
                    .thenAnswer(call -> {
                        opens.incrementAndGet();
                        return client;
                    });
            org.mockito.Mockito
                    .when(client.namespace("runtime"))
                    .thenAnswer(call -> JSON.writeValueAsBytes(api.namespace));
            org.mockito.Mockito
                    .when(client.configMap("runtime", "runtime-trust"))
                    .thenAnswer(call -> JSON.writeValueAsBytes(api.configMap));
            org.mockito.Mockito.when(client.cleanupUncertain()).thenAnswer(call -> uncertain.get());
            var source = new AiRuntimeNativeMaterialPublisher.Source(configuration, "runtime", NAMESPACE_UID,
                    "runtime-trust", CONFIG_UID);
            var publisher = new AiRuntimeNativeMaterialPublisher(source, api.clock);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            uncertain.set(false);
            publisher.refresh(AiRuntimeOperationBudget.start());
            assertThat(publisher.get()).isNull();
            assertThat(opens).hasValue(1);
            var independent = new AiRuntimeNativeMaterialPublisher(source, api.clock);
            independent.refresh(AiRuntimeOperationBudget.start());
            assertThat(independent.get()).isNotNull();
            assertThat(opens).hasValue(2);
        }
    }

    private static final class Api implements AutoCloseable {
        private final RuntimeProxyTrustManagerTest.Identity authority;
        private final HttpsServer server;
        private final java.util.concurrent.ExecutorService executor = Executors.newFixedThreadPool(2);
        private final Path ca;
        private final Path token;
        private final MutableClock clock = new MutableClock();
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger methods = new AtomicInteger();
        private final List<String> paths = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final AtomicInteger namespaceReads = new AtomicInteger();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile boolean block;
        private volatile int status = 200;
        private volatile ObjectNode namespace;
        private volatile ObjectNode laterNamespace;
        private volatile byte[] rawNamespace;
        private volatile ObjectNode configMap;
        private final ObjectNode policy;

        private Api(Path directory) throws Exception {
            Instant now = clock.instant();
            authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(60), now.plusSeconds(600));
            var leaf = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "kube.invalid")), now.minusSeconds(30),
                    now.plusSeconds(300));
            var keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("server", leaf.keys().getPrivate(), new char[0], chain(leaf, authority));
            var managers = KeyManagerFactory.getInstance("SunX509");
            managers.init(keys, new char[0]);
            var tls = SSLContext.getInstance("TLS");
            tls.init(managers.getKeyManagers(), null, null);
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(tls));
            server.setExecutor(executor);
            namespace = object("Namespace", "runtime", NAMESPACE_UID, "1");
            configMap = object("ConfigMap", "runtime-trust", CONFIG_UID, "11");
            ((ObjectNode) configMap.get("metadata")).put("namespace", "runtime");
            policy = JSON.createObjectNode().put("version", 1).put("revision", 1);
            policy
                    .putArray("authorities")
                    .addObject()
                    .put("cluster", "lab")
                    .put("certificateDerBase64",
                            Base64.getEncoder().encodeToString(authority.certificate().getEncoded()));
            policy.putArray("deniedTbsFingerprints").add("1".repeat(64));
            publishPolicy("11");
            ca = Files.createTempFile(directory, "ca-", ".der");
            Files.write(ca, authority.certificate().getEncoded());
            token = Files.createTempFile(directory, "synthetic-", ".token");
            Files.writeString(token, "synthetic.publisher.token");
            Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
            server.createContext("/", exchange -> {
                try (exchange) {
                    requests.incrementAndGet();
                    if (!"GET".equals(exchange.getRequestMethod()) || !"Bearer synthetic.publisher.token"
                            .equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                        methods.incrementAndGet();
                    }
                    if (block) {
                        entered.countDown();
                        try {
                            release.await(4, TimeUnit.SECONDS);
                        } catch (InterruptedException stopped) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    String path = exchange.getRequestURI().toString();
                    paths.add(path);
                    ObjectNode observed = configMap;
                    if (NAMESPACE_PATH.equals(path)) {
                        observed = namespaceReads.incrementAndGet() > 1 && laterNamespace != null
                                ? laterNamespace
                                : namespace;
                    }
                    byte[] body = NAMESPACE_PATH.equals(path) && rawNamespace != null
                            ? rawNamespace
                            : JSON.writeValueAsBytes(observed);
                    int response = NAMESPACE_PATH.equals(path) || POLICY_PATH.equals(path) ? status : 404;
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(response, body.length);
                    exchange.getResponseBody().write(body);
                }
            });
            server.start();
        }

        private void publishPolicy(String resourceVersion) {
            ((ObjectNode) configMap.get("metadata")).put("resourceVersion", resourceVersion);
            configMap.putObject("data").put("policy.json", policy.toString());
        }

        private AiRuntimeNativeMaterialPublisher publisher() {
            return new AiRuntimeNativeMaterialPublisher(source(), clock);
        }

        private AiRuntimeNativeMaterialPublisher.Source source() {
            return new AiRuntimeNativeMaterialPublisher.Source(configuration(), "runtime", NAMESPACE_UID,
                    "runtime-trust", CONFIG_UID);
        }

        private KubernetesConfiguration configuration() {
            var endpoint = new CoreEndpoint(URI.create("https://kube.invalid:" + server.getAddress().getPort()),
                    InetAddress.getLoopbackAddress());
            return new KubernetesConfiguration(endpoint, ca, token);
        }

        private static ObjectNode object(String kind, String name, UUID uid, String rv) {
            ObjectNode value = JSON.createObjectNode().put("apiVersion", "v1").put("kind", kind);
            value.putObject("metadata").put("name", name).put("uid", uid.toString()).put("resourceVersion", rv);
            return value;
        }

        @Override
        public void close() throws Exception {
            release.countDown();
            server.stop(0);
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.now());

        private void advance(Duration duration) {
            now.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}
