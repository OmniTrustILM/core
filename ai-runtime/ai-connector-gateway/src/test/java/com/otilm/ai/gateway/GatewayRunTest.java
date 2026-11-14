package com.otilm.ai.gateway;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayRunTest {
    @TempDir
    Path directory;

    @Test
    void providerIdentityOracleDetectsAnExplicitlyOfferedSyntheticCoreCertificate() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            var offered = com.otilm.ai.proxy.IdentityFiles
                    .load(directory.resolve("tls.crt"), directory.resolve("tls.key"),
                            directory.resolve("provider-ca.pem"));
            var endpoint = new PinnedEndpoint(
                    java.net.URI.create("https://provider.test:" + f.provider.getAddress().getPort()),
                    java.util.List.of(java.net.InetAddress.getLoopbackAddress()), offered);
            assertArrayEquals(f.providerReply,
                    new ChatCompletionsTransport()
                            .post(endpoint, GatewayRunWireTest.PAYLOAD, GatewayRunWireTest.ENVELOPE.payloadSha256(),
                                    "synthetic-oracle-token"));
            assertTrue(f.providerReceivedClientIdentity);
            assertEquals(1, f.sends.get());
            assertEquals(0, f.consumes.get());
        }
    }

    @Test
    void aForeignCoreCaCannotReachEitherHttpChannel() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            var config = (com.fasterxml.jackson.databind.node.ObjectNode) GatewayRunWireTest.JSON
                    .readTree(Files.readAllBytes(f.config));
            config.put("serverCaFile", directory.resolve("provider-ca.pem").toString());
            Files.write(f.config, GatewayRunWireTest.JSON.writeValueAsBytes(config));
            assertThrows(GatewayFailure.class, () -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL));
            assertEquals(0, f.consumes.get());
            assertEquals(0, f.sends.get());
            assertEquals(0, f.outcomes.get());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"foreign-ca", "leaf-as-ca"})
    void providerTrustFailureAfterConsumeReportsOnlyUnknownWithoutSendingHeaders(String mode) throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            var config = (com.fasterxml.jackson.databind.node.ObjectNode) GatewayRunWireTest.JSON
                    .readTree(Files.readAllBytes(f.config));
            config
                    .put("providerCaFile",
                            directory.resolve(mode.equals("foreign-ca") ? "ca.pem" : "tls.crt").toString());
            Files.write(f.config, GatewayRunWireTest.JSON.writeValueAsBytes(config));
            assertThrows(GatewayFailure.class, () -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL));
            assertEquals(1, f.consumes.get());
            assertEquals(0, f.sends.get());
            assertEquals(1, f.outcomes.get());
            assertEquals("UNKNOWN",
                    GatewayRunWireTest.JSON.readTree(f.outcomeRequest).get("transportCode").textValue());
        }
    }

    @Test
    void fixedCoreCallsRetainTheAdministratorServletContext() throws Exception {
        try (var f = new GatewayRunFixture(directory, "/api")) {
            assertEquals(9, assertDoesNotThrow(() -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL)));
            assertEquals(1, f.consumes.get());
            assertEquals(1, f.sends.get());
            assertEquals(1, f.outcomes.get());
        }
    }

    @Test
    void ownsActualConsumeProviderAndProtectedOutcomeWithOneCorrelation() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            assertEquals(9, assertDoesNotThrow(() -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL)));
            assertEquals(1, f.consumes.get());
            assertEquals(1, f.sends.get());
            assertEquals(1, f.outcomes.get());
            assertArrayEquals(GatewayRunWireTest.PAYLOAD, f.providerRequest);
            assertEquals("Bearer " + GatewayRunFixture.TOKEN, f.providerAuthorization);
            assertNull(f.providerCookie);
            assertNull(f.coreAuthorization);
            assertFalse(f.coreSawAuthorization.get());
            assertFalse(f.coreSawCookie.get());
            assertFalse(f.providerReceivedClientIdentity);
            var outcome = GatewayRunWireTest.JSON.readTree(f.outcomeRequest);
            assertArrayEquals(f.providerReply,
                    java.util.Base64.getDecoder().decode(outcome.get("responseBase64").textValue()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "deny",
            "wrong-binding",
            "cookie",
            "cookie2",
            "mime",
            "charset",
            "encoding",
            "no-mime",
            "empty",
            "no-entity"})
    void deniedOrUnboundOrSessionBearingConsumeCannotReachProviderOrOutcome(String mode) throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            f.mode = mode;
            Files.delete(f.secret);
            assertThrows(GatewayFailure.class, () -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL));
            assertEquals(1, f.consumes.get());
            assertEquals(0, f.sends.get());
            assertEquals(0, f.outcomes.get());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing-secret", "reflected", "escaped", "bad-ack"})
    void consumedFailuresNeverRetryAndRetainOnlySafeUnknownEvidence(String mode) throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            if (mode.equals("missing-secret")) {
                Files.delete(f.secret);
            }
            if (mode.equals("reflected")) {
                f.providerReply = ("{\"text\":\"" + GatewayRunFixture.TOKEN + "\"}").getBytes(StandardCharsets.UTF_8);
            }
            if (mode.equals("escaped")) {
                f.providerReply = "{\"text\":\"SYNTHETIC_\\u0054RANSPORT_CANARY\"}".getBytes(StandardCharsets.UTF_8);
            }
            if (mode.equals("bad-ack")) {
                f.mode = mode;
            }
            assertThrows(GatewayFailure.class, () -> GatewayRun
                    .execute(f.envelope, f.config, new ChatCompletionsTransport(), GatewayRunWireTest.CALL));
            assertEquals(1, f.consumes.get());
            assertEquals(mode.equals("missing-secret") ? 0 : 1, f.sends.get());
            assertEquals(1, f.outcomes.get());
            if (!mode.equals("bad-ack")) {
                var report = GatewayRunWireTest.JSON.readTree(f.outcomeRequest);
                assertEquals("UNKNOWN", report.get("transportCode").textValue());
                assertTrue(report.get("responseBase64").isNull());
            }
        }
    }

    @Test
    void consumeCannotResetTheOriginalOperationDeadline() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            f.consumeDelayMillis = 1500;
            var transport = new ChatCompletionsTransport(Duration.ofMillis(350), Duration.ofSeconds(1),
                    Thread.ofPlatform().daemon().factory());
            long start = System.nanoTime();
            assertThrows(GatewayFailure.class,
                    () -> GatewayRun.execute(f.envelope, f.config, transport, GatewayRunWireTest.CALL));
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
            assertEquals(1, f.consumes.get());
            assertEquals(0, f.sends.get());
        }
    }

    @Test
    void invalidPositiveReplyCannotBeUsedToReportAnOutcomeThroughTheSameClient() throws Exception {
        try (var f = new GatewayRunFixture(directory)) {
            f.mode = "wrong-binding";
            var client = new CoreRunClient(GatewayRunConfiguration.read(f.config));
            var transport = new ChatCompletionsTransport();
            try (var operation = transport.admit(transport.accepted())) {
                assertThrows(GatewayFailure.class,
                        () -> client.consume(GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL, operation));
                byte[] report = GatewayRunWire.outcome(GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL, null);
                assertThrows(GatewayFailure.class,
                        () -> client.report(GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL, report, operation));
            }
            assertEquals(1, f.consumes.get());
            assertEquals(0, f.outcomes.get());
        }
    }
}
