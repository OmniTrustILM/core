package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Local client binding only; the synthetic endpoint is not Core business authorization. */
class CoreClientBindingTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"intent", "binding", "digest", "correlation"})
    void aValidConsumeCannotBeReportedWithAnotherEnvelopeOrCorrelation(String mode) throws Exception {
        try (var fixture = new GatewayRunFixture(directory)) {
            var client = new CoreRunClient(GatewayRunConfiguration.read(fixture.config));
            var transport = new ChatCompletionsTransport();
            try (var operation = transport.admit(transport.accepted())) {
                client.consume(GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL, operation);
                var original = GatewayRunWireTest.ENVELOPE;
                var old = original.binding();
                var envelope = switch (mode) {
                    case "intent" -> new RunDispatchEnvelope(1, UUID.fromString("00000000-0000-4000-8000-000000000201"),
                            original.payloadSha256(), old);
                    case "binding" -> new RunDispatchEnvelope(1, original.intentId(), original.payloadSha256(),
                            new RunBinding(old.runId(), old.attemptId(), old.podUid(), old.claimId(), old.fence() + 1,
                                    old.expiresAt()));
                    case "digest" -> new RunDispatchEnvelope(1, original.intentId(), "a".repeat(64), old);
                    default -> original;
                };
                var correlation = mode.equals("correlation")
                        ? UUID.fromString("00000000-0000-4000-8000-000000000202")
                        : GatewayRunWireTest.CALL;
                byte[] outcome = GatewayRunWire.outcome(envelope, correlation, null);
                assertThrows(GatewayFailure.class, () -> client.report(envelope, correlation, outcome, operation));
            }
            assertEquals(1, fixture.consumes.get());
            assertEquals(0, fixture.outcomes.get());
            assertEquals(0, fixture.sends.get());
        }
    }
}
