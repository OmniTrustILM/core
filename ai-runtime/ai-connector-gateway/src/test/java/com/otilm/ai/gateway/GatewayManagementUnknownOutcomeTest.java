package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.ManagementAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayManagementUnknownOutcomeTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"missing-credential", "provider-failure", "reflected-credential"})
    void consumedManagementFailureReportsOnlyManagementUnknownEvidenceWithoutRunFields(String mode) throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "/api", ManagementAction.CONNECTION_CHECK)) {
            switch (mode) {
                case "missing-credential" -> Files.delete(fixture.secret);
                case "provider-failure" -> fixture.providerStatus = 500;
                case "reflected-credential" ->
                    fixture.providerReply = ("{\"answer\":\"" + GatewayRunFixture.TOKEN + "\"}")
                            .getBytes(StandardCharsets.UTF_8);
            }
            assertThrows(GatewayFailure.class,
                    () -> GatewayRun
                            .executeManagement(fixture.envelope, fixture.config, new ChatCompletionsTransport(),
                                    GatewayManagementWireTest.CALL));
            assertEquals(1, fixture.consumes.get());
            assertEquals(mode.equals("missing-credential") ? 0 : 1, fixture.sends.get());
            assertEquals(1, fixture.outcomes.get());
            assertEquals(3, fixture.coreRequests.get());
            assertEquals(1, fixture.registrations.get());
            var root = GatewayManagementWireTest.JSON.readTree(fixture.outcomeRequest);
            var names = new HashSet<String>();
            root.get("binding").fieldNames().forEachRemaining(names::add);
            assertEquals(
                    Set.of("actorId", "sessionId", "configurationId", "configurationRevision", "action", "expiresAt"),
                    names);
            assertEquals("management-outcome", root.get("kind").textValue());
            assertEquals("UNKNOWN", root.get("transportCode").textValue());
            assertTrue(root.get("responseBase64").isNull());
            assertTrue(root.get("responseSha256").isNull());
            assertEquals(0, root.get("responseByteCount").intValue());
            assertEquals("unknown", root.get("usage").get("kind").textValue());
            assertNull(fixture.coreAuthorization);
        }
    }
}
