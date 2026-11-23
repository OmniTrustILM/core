package com.otilm.core.service.ai;

import com.otilm.ai.controller.ControllerWire;
import com.otilm.api.exception.PlatformException;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Closed route dispatch over the shared codec; these metadata values confer no transport or controller authority. */
class AiRuntimeControllerWireTest {
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    private static final UUID POD = UUID.fromString("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3");
    private static final ControllerWire.Control CURRENT = new ControllerWire.Control(LOCATOR, 8, 4,
            UUID.fromString("736947e7-2778-4b40-8b0b-a514e319113c"), Set.of(new ControllerWire.Pod("lab", POD)));

    @Test
    void returnsSafeDomainMessage_whenControllerMetadataContainsPrivateDetail() {
        // given
        var providerCanary = "SYNTHETIC_PROVIDER_SECRET_CANARY";
        byte[] malformed = ("{\"private\":\"" + providerCanary + "\"}")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // when
        ThrowingCallable readMetadata = () -> AiRuntimeControllerWire
                .read(malformed, AiRuntimeControllerWire.Route.RECONCILE);

        // then
        assertThatThrownBy(readMetadata)
                .isInstanceOfSatisfying(AiRuntimeControllerWire.Invalid.class,
                        failure -> assertThat(PlatformException.safeMessage(failure, "fallback"))
                                .isEqualTo("INVALID_CONTROLLER_METADATA")
                                .doesNotContain(providerCanary))
                .hasNoCause();
    }

    @Test
    void reconcileDistinguishesNoPodCanonicalLaunchFromActualPodEligibility() {
        var launch = assertDoesNotThrow(() -> AiRuntimeControllerWire
                .read(ControllerWire.launchRequest(LOCATOR), AiRuntimeControllerWire.Route.RECONCILE));
        assertEquals(AiRuntimeControllerWire.Kind.LAUNCH, launch.kind());
        assertEquals(LOCATOR, launch.locator());
        var eligible = assertDoesNotThrow(() -> AiRuntimeControllerWire
                .read(ControllerWire
                        .observationRequest(ControllerWire.Operation.ELIGIBLE,
                                new ControllerWire.ObservationRequest(LOCATOR, POD)),
                        AiRuntimeControllerWire.Route.RECONCILE));
        assertEquals(AiRuntimeControllerWire.Kind.ELIGIBLE, eligible.kind());
        assertEquals(POD, eligible.podUid());
    }

    @Test
    void delegatedSdkParserRetainsClosedFieldsStrictUtf8DuplicateAndTrailingRejection() {
        String valid = new String(ControllerWire.launchRequest(LOCATOR), java.nio.charset.StandardCharsets.UTF_8);
        for (byte[] body : new byte[][]{
                valid
                        .replace("\"version\":1", "\"version\":1,\"version\":1")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8),
                (valid + " {}").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                valid.getBytes(java.nio.charset.StandardCharsets.UTF_16),
                valid.replace("\"version\":1", "\"version\":true").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                valid
                        .replace("\"version\":1", "\"version\":1,\"role\":\"CONTROLLER\"")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8),
                valid
                        .replace(LOCATOR.runId().toString(), "00000000-0000-0000-0000-000000000000")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)}) {
            assertThrows(AiRuntimeControllerWire.Invalid.class,
                    () -> AiRuntimeControllerWire.read(body, AiRuntimeControllerWire.Route.RECONCILE));
        }
    }

    @Test
    void registeredObservationCannotBeSelectedByAnotherPhysicalRoute() {
        var body = ControllerWire
                .observationRequest(ControllerWire.Operation.REGISTER,
                        new ControllerWire.ObservationRequest(LOCATOR, POD));
        var request = assertDoesNotThrow(
                () -> AiRuntimeControllerWire.read(body, AiRuntimeControllerWire.Route.REGISTER));
        assertEquals(AiRuntimeControllerWire.Kind.REGISTER, request.kind());
        for (var route : new AiRuntimeControllerWire.Route[]{
                AiRuntimeControllerWire.Route.RECONCILE,
                AiRuntimeControllerWire.Route.STATUS,
                AiRuntimeControllerWire.Route.CLEANUP}) {
            assertThrows(AiRuntimeControllerWire.Invalid.class, () -> AiRuntimeControllerWire.read(body, route));
        }
    }

    @Test
    void locatorOnlyResumptionIsAvailableOnlyOnTheAuthenticatedStatusRoute() {
        byte[] body = ControllerWire.cleanupResumeRequest(LOCATOR);
        var request = AiRuntimeControllerWire.read(body, AiRuntimeControllerWire.Route.STATUS);
        assertEquals(AiRuntimeControllerWire.Kind.RESUME, request.kind());
        assertEquals(LOCATOR, request.locator());
        for (var route : new AiRuntimeControllerWire.Route[]{
                AiRuntimeControllerWire.Route.RECONCILE,
                AiRuntimeControllerWire.Route.REGISTER,
                AiRuntimeControllerWire.Route.CLEANUP}) {
            assertThrows(AiRuntimeControllerWire.Invalid.class, () -> AiRuntimeControllerWire.read(body, route));
        }
    }

    @Test
    void statusAndCleanupRoutesKeepTheirClosedOperations() {
        for (var operation : ControllerWire.ControlOperation.values()) {
            var expected = operation == ControllerWire.ControlOperation.TERMINAL
                    || operation == ControllerWire.ControlOperation.CLEANUP ? CURRENT : null;
            var body = ControllerWire.controlRequest(operation, LOCATOR, expected);
            var route = operation == ControllerWire.ControlOperation.STATUS
                    || operation == ControllerWire.ControlOperation.TERMINAL
                            ? AiRuntimeControllerWire.Route.STATUS
                            : AiRuntimeControllerWire.Route.CLEANUP;
            var request = assertDoesNotThrow(() -> AiRuntimeControllerWire.read(body, route));
            assertEquals(operation.name(), request.kind().name());
            assertEquals(LOCATOR, request.locator());
            assertEquals(expected, request.expected());
            assertThrows(AiRuntimeControllerWire.Invalid.class,
                    () -> AiRuntimeControllerWire.read(body, AiRuntimeControllerWire.Route.REGISTER));
        }
    }

    @Test
    void malformedOrUnknownMetadataNeverSelectsAnEffect() {
        for (byte[] body : new byte[][]{
                null,
                new byte[0],
                new byte[4097],
                "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "{\"version\":1,\"kind\":\"arbitrary-exec\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8)}) {
            for (var route : AiRuntimeControllerWire.Route.values()) {
                var failure = assertThrows(AiRuntimeControllerWire.Invalid.class,
                        () -> AiRuntimeControllerWire.read(body, route));
                assertEquals("INVALID_CONTROLLER_METADATA", failure.getMessage());
                assertEquals(0, failure.getStackTrace().length);
            }
        }
    }
}
