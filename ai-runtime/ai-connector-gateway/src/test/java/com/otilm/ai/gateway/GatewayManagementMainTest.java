package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.ManagementAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayManagementMainTest {
    @TempDir
    Path directory;

    @Test
    void actualManagementChildReportsProtectedProbeWithOnlyFixedMetadata() throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "/api", ManagementAction.CAPABILITY_CHECK)) {
            var result = GatewayRunMainTest
                    .child("com.otilm.ai.gateway.GatewayManagementMain",
                            List.of(fixture.envelope.toString(), fixture.config.toString()));
            assertEquals(0, result.exit());
            assertTrue(result
                    .output()
                    .matches("phase=gateway op=management-outcome code=RECORDED correlation=[0-9a-f-]{36}\\R"));
            assertEquals("", result.error());
            assertEquals(3, fixture.coreRequests.get());
            assertEquals(1, fixture.registrations.get());
            assertEquals(1, fixture.consumes.get());
            assertEquals(1, fixture.sends.get());
            assertEquals(1, fixture.outcomes.get());
            assertEquals(List.of("registration", "consume", "outcome"), fixture.coreTrace);
            var envelope = GatewayManagementWireTest.JSON.readTree(fixture.consumeRequest).path("envelope");
            assertEquals("management", envelope.path("kind").textValue());
            assertEquals(ManagementAction.CAPABILITY_CHECK.name(), envelope.path("binding").path("action").textValue());
            assertFalse(envelope.path("binding").has("runId"));
            assertFalse(envelope.path("binding").has("claimId"));
            assertFalse(envelope.path("binding").has("podUid"));
            assertFalse(result.output().contains("public reply"));
            assertFalse(result.output().contains(GatewayRunFixture.TOKEN));
            assertFalse(result.output().contains(directory.toString()));
        }
    }

    @Test
    void aManagementChildCannotUseARunEnvelopeToSelectTheRunAudience() throws Exception {
        try (var fixture = new GatewayRunFixture(directory, "", ManagementAction.CONNECTION_CHECK)) {
            Files.write(fixture.envelope, GatewayRunWireTest.PROTOCOL.writeDispatch(GatewayRunWireTest.ENVELOPE));
            Files.delete(fixture.secret);
            var result = GatewayRunMainTest
                    .child("com.otilm.ai.gateway.GatewayManagementMain",
                            List.of(fixture.envelope.toString(), fixture.config.toString()));
            assertEquals(1, result.exit());
            assertTrue(result.output().contains("code=UNKNOWN"));
            assertEquals("", result.error());
            assertEquals(0, fixture.coreRequests.get());
            assertEquals(0, fixture.registrations.get());
            assertEquals(0, fixture.consumes.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
        }
    }
}
