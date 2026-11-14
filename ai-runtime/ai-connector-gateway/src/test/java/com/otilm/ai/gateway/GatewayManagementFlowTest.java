package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.ManagementAction;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Local transport oracle only; actual management actor/session/CONNECT authority stays in Core. */
class GatewayManagementFlowTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @EnumSource(ManagementAction.class)
    void performsExactlyOneManagementConsumeProviderAndProtectedOutcomeWithoutARun(ManagementAction action)
            throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "/api", action)) {
            assertEquals(9, assertDoesNotThrow(() -> execute(fixture)));
            assertEquals(3, fixture.coreRequests.get());
            assertEquals(1, fixture.registrations.get());
            assertEquals(java.util.List.of("registration", "consume", "outcome"), fixture.coreTrace);
            assertEquals(1, fixture.consumes.get());
            assertEquals(1, fixture.sends.get());
            assertEquals(1, fixture.outcomes.get());
            assertArrayEquals(GatewayManagementWireTest.PAYLOAD, fixture.providerRequest);
            var request = GatewayManagementWireTest.JSON.readTree(fixture.consumeRequest);
            var binding = request.get("envelope").get("binding");
            assertEquals("management", request.get("envelope").get("kind").textValue());
            assertEquals(action.name(), binding.get("action").textValue());
            assertFalse(binding.has("runId"));
            assertFalse(binding.has("claimId"));
            assertFalse(binding.has("podUid"));
            assertFalse(fixture.coreSawAuthorization.get());
            assertFalse(fixture.coreSawCookie.get());
            assertFalse(fixture.providerReceivedClientIdentity);
            assertEquals("management-outcome",
                    GatewayManagementWireTest.JSON.readTree(fixture.outcomeRequest).get("kind").textValue());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"deny", "wrong-kind", "wrong-binding", "cookie", "bad-ack"})
    void ambiguousOrUnboundManagementControlNeverRetriesOrFabricatesARunGrant(String mode) throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "", ManagementAction.CONNECTION_CHECK)) {
            fixture.mode = mode;
            assertThrows(GatewayFailure.class, () -> execute(fixture));
            assertEquals(1, fixture.consumes.get());
            assertEquals(mode.equals("bad-ack") ? 1 : 0, fixture.sends.get());
            assertEquals(mode.equals("bad-ack") ? 1 : 0, fixture.outcomes.get());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"management-to-run", "run-to-management"})
    void eachFixedEntryDeniesTheOtherEnvelopeBeforeAnyCoreRequest(String mode) throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "", ManagementAction.CONNECTION_CHECK)) {
            Files.delete(fixture.secret);
            if (mode.equals("management-to-run")) {
                assertThrows(GatewayFailure.class,
                        () -> GatewayRun
                                .execute(fixture.envelope, fixture.config, new ChatCompletionsTransport(),
                                        GatewayManagementWireTest.CALL));
            } else {
                Files.write(fixture.envelope, GatewayRunWireTest.PROTOCOL.writeDispatch(GatewayRunWireTest.ENVELOPE));
                assertThrows(GatewayFailure.class, () -> execute(fixture));
            }
            assertEquals(0, fixture.coreRequests.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
        }
    }

    private static long execute(GatewayRunFixture fixture) {
        return GatewayRun
                .executeManagement(fixture.envelope, fixture.config, new ChatCompletionsTransport(),
                        GatewayManagementWireTest.CALL);
    }
}
