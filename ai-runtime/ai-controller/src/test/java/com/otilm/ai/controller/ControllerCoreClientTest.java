package com.otilm.ai.controller;

import com.otilm.ai.proxy.CoreEndpoint;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Actual local mTLS proves transport behavior, not Core current-registration or business-authority production gates.
 */
class ControllerCoreClientTest {
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    @TempDir
    Path directory;

    @Test
    void fixedCoreBaseContextUsesOneMtlsPostWithoutApiBearerAndRequiresMatchingCanonicalReply() throws Exception {
        try (var server = new KubernetesHttpsFixture(200,
                ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
            server.requireClientAuthentication = true;
            var client = new ControllerCoreClient(configuration(server));
            var binding = assertDoesNotThrow(() -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertEquals(LOCATOR, binding.locator());
            assertEquals("POST", server.method.get());
            assertEquals("/api/internal/ai-runtime/v1/controller/launches/reconcile", server.path.get());
            assertEquals(1, server.authenticatedClients.get());
            assertNull(server.authorization.get());
            assertNull(server.acceptEncoding.get());
            assertEquals(new String(ControllerWire.launchRequest(LOCATOR), StandardCharsets.UTF_8),
                    new String(server.received.get(), StandardCharsets.UTF_8));
            assertFalse(client.outcomeUnknown());
            assertFalse(client.cleanupUncertain());
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void errorsChallengesAndMismatchedAcknowledgementsNeverCauseAnotherCoreRequest() throws Exception {
        for (int status : new int[]{301, 401, 407, 408, 421, 503, 101}) {
            try (var server = new KubernetesHttpsFixture(status,
                    ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
                server.requireClientAuthentication = true;
                var client = new ControllerCoreClient(configuration(server));
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
                assertTrue(client.outcomeUnknown());
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
                assertEquals(1, server.requests.get(), "wire attempts for " + status);
            }
        }
        String mismatched = ControllerWireTest.BINDING
                .replace(LOCATOR.correlationId().toString(), UUID.randomUUID().toString());
        try (var server = new KubernetesHttpsFixture(200, mismatched.getBytes(StandardCharsets.UTF_8))) {
            var client = new ControllerCoreClient(configuration(server));
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertTrue(client.outcomeUnknown());
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void aStalledCoreBodyCannotResetTheWholePhaseBudgetOrLeaveAnOwnedGuard() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            var configuration = configuration(server);
            new KubernetesApi(server.endpoint(), server.trust(), configuration.kubernetes().tokenFile(),
                    Duration.ofSeconds(5)).namespace("warm");
            server.slowThenStall = true;
            var client = new ControllerCoreClient(configuration);
            long started = System.nanoTime();
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofMillis(400)));
            assertTrue(System.nanoTime() - started < Duration.ofMillis(700).toNanos());
            assertTrue(client.outcomeUnknown());
            assertFalse(client.cleanupUncertain());
            assertFalse(Thread
                    .getAllStackTraces()
                    .keySet()
                    .stream()
                    .anyMatch(t -> t.isAlive() && t.getName().equals("ai-controller-core-budget")));
        }
    }

    @Test
    void aReplyCannotBecomeSuccessfulAfterCleanupConsumesTheRemainingPhaseBudget() throws Exception {
        try (var server = new KubernetesHttpsFixture(200,
                ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
            var configuration = configuration(server);
            new ControllerCoreClient(configuration).launch(LOCATOR, Duration.ofSeconds(5));
            var client = new ControllerCoreClient(configuration, active -> {
                active.run();
                try {
                    Thread.sleep(1200);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("synthetic interrupted close");
                }
            });
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(1)));
            assertEquals(2, server.requests.get());
            assertTrue(client.outcomeUnknown());
        }
    }

    @Test
    void cleanupFailureIsRetainedAndCannotBeReportedAsKnownClosedOrSuccessful() throws Exception {
        try (var server = new KubernetesHttpsFixture(200,
                ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
            var client = new ControllerCoreClient(configuration(server), active -> {
                active.run();
                throw new IllegalStateException("synthetic-private-cleanup-canary");
            });
            var failure = assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertEquals("OBSERVATION_UNAVAILABLE", failure.getMessage());
            assertNull(failure.getCause());
            assertTrue(client.cleanupUncertain());
            assertTrue(client.outcomeUnknown());
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void encodingCookiesForeignContentTypesAndOversizedResponsesAreRejectedWithoutDrainOrRetry() throws Exception {
        for (String defect : new String[]{
                "encoding",
                "cookie",
                "content-type",
                "charset",
                "unknown-charset",
                "duplicate-type",
                "declared-size",
                "chunked-size",
                "empty"}) {
            byte[] body = defect.equals("declared-size")
                    ? new byte[4097]
                    : defect.equals("empty")
                            ? new byte[0]
                            : ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8);
            try (var server = new KubernetesHttpsFixture(200, body)) {
                switch (defect) {
                    case "encoding" -> server.encoding = "gzip";
                    case "cookie" -> server.cookie = "synthetic.session=value";
                    case "content-type" -> server.replyContentType = "text/plain";
                    case "charset" -> server.replyContentType = "application/json; charset=ISO-8859-1";
                    case "unknown-charset" -> server.replyContentType = "application/json; charset=not-a-real-charset";
                    case "duplicate-type" -> server.extraContentType = "application/json";
                    case "chunked-size" -> server.hostileChunked = true;
                    default -> {
                    }
                }
                var client = new ControllerCoreClient(configuration(server));
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)), defect);
                assertTrue(client.outcomeUnknown());
                assertFalse(client.cleanupUncertain());
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void commaJoinedOrParameterizedMediaTypesCannotBecomeACanonicalCoreReply() throws Exception {
        for (String type : new String[]{
                "application/json, text/plain",
                "application/json; charset=UTF-8, text/plain",
                "application/json; profile=foreign",
                "application/json; charset=UTF-8; charset=ISO-8859-1",
                "application/json" + " ".repeat(480) + "!",
                "application/json" + "\t".repeat(480) + "!",
                "application/json" + " \t".repeat(240) + "; charset=UTF-8!",
                "application/json;" + " \t".repeat(240) + "charset=\"utf-8"}) {
            try (var server = new KubernetesHttpsFixture(200,
                    ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
                server.replyContentType = type;
                var client = new ControllerCoreClient(configuration(server));
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)), type);
                assertTrue(client.outcomeUnknown());
                assertFalse(client.cleanupUncertain());
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void aSingleUtf8JsonMediaTypeRemainsCompatible() throws Exception {
        for (String type : new String[]{
                "Application/JSON",
                "application/json; charset=UTF-8",
                "application/json ; charset = \"utf-8\"",
                "application/json" + " ".repeat(480) + "; charset=UTF-8",
                "application/json" + "\t".repeat(480) + "; charset=UTF-8",
                "application/json" + " \t".repeat(80) + ";" + " \t".repeat(80) + "charset" + " \t".repeat(80) + "="
                        + " \t".repeat(80) + "\"utf-8\"" + " \t".repeat(80)}) {
            try (var server = new KubernetesHttpsFixture(200,
                    ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
                server.replyContentType = type;
                assertDoesNotThrow(
                        () -> new ControllerCoreClient(configuration(server)).launch(LOCATOR, Duration.ofSeconds(5)));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void invalidOrInterruptedPhaseBudgetsAndMissingIdentityDenyBeforeCoreIo() throws Exception {
        try (var server = new KubernetesHttpsFixture(200,
                ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8))) {
            var configuration = configuration(server);
            for (Duration budget : new Duration[]{null, Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(6)}) {
                var client = new ControllerCoreClient(configuration);
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, budget));
                assertFalse(client.outcomeUnknown());
            }
            Thread.currentThread().interrupt();
            try {
                assertThrows(ObservationFailure.class,
                        () -> new ControllerCoreClient(configuration).launch(LOCATOR, Duration.ofSeconds(5)));
            } finally {
                Thread.interrupted();
            }
            Files.delete(configuration.privateKeyFile());
            var client = new ControllerCoreClient(configuration);
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, Duration.ofSeconds(5)));
            assertFalse(client.outcomeUnknown());
            assertEquals(0, server.requests.get());
        }
    }

    ControllerConfiguration configuration(KubernetesHttpsFixture server) throws Exception {
        Path identity = Files.createTempDirectory(directory, "identity-");
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        Instant now = Instant.now();
        var certificate = new JcaX509v3CertificateBuilder(new X500Name(server.ca.getSubjectX500Principal().getName()),
                new BigInteger(128, new java.security.SecureRandom()), Date.from(now.minusSeconds(30)),
                Date.from(now.plusSeconds(300)), new X500Name("CN=synthetic-controller"), pair.getPublic());
        certificate.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificate.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        certificate
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        certificate
                .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        "ilm-runtime-controller://lab/ns/runtime/sa/controller/pod/controller-one/uid/46a31e2d-c99b-4b34-853c-d92738fca27c")));
        var leaf = new JcaX509CertificateConverter()
                .getCertificate(certificate
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(server.caKeys.getPrivate())));
        Path cert = identity.resolve("tls.crt");
        Path key = identity.resolve("tls.key");
        Path ca = identity.resolve("ca.pem");
        Files.writeString(cert, pem("CERTIFICATE", leaf.getEncoded()));
        Files.writeString(key, pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        Files.writeString(ca, pem("CERTIFICATE", server.ca.getEncoded()));
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
        Path token = identity.resolve("api.token");
        Files.writeString(token, "synthetic.api.token");
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        var endpoint = new CoreEndpoint(URI.create(server.endpoint().origin().toString() + "/api"),
                server.endpoint().address());
        return new ControllerConfiguration(endpoint, cert, key, ca,
                new KubernetesConfiguration(server.endpoint(), ca, token), identity.resolve("public-profile.json"));
    }

    private static String pem(String type, byte[] bytes) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n";
    }
}
