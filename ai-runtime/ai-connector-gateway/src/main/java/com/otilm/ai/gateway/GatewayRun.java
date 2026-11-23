package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.DispatchEnvelope;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;

/** One finite gateway operation; labels and component fixtures never supply Core authority. */
final class GatewayRun {
    enum Audience {
        RUN,
        MANAGEMENT;

        boolean accepts(DispatchEnvelope envelope) {
            return switch (this) {
                case RUN -> envelope instanceof RunDispatchEnvelope;
                case MANAGEMENT -> envelope instanceof ManagementDispatchEnvelope;
            };
        }

        String redeemPath() {
            return switch (this) {
                case RUN -> "/internal/ai-runtime/v1/gateway/run/redeem";
                case MANAGEMENT -> "/internal/ai-management/v1/gateway/redeem";
            };
        }

        String registrationPath() {
            return switch (this) {
                case RUN -> "/internal/ai-runtime/v1/gateway/run/registration";
                case MANAGEMENT -> "/internal/ai-management/v1/gateway/registration";
            };
        }

        String outcomePath() {
            return switch (this) {
                case RUN -> "/internal/ai-runtime/v1/gateway/run/outcomes";
                case MANAGEMENT -> "/internal/ai-management/v1/gateway/outcomes";
            };
        }

        String operation() {
            return this == RUN ? "outcome" : "management-outcome";
        }
    }

    static long execute(Path envelope, Path configuration, ChatCompletionsTransport transport, UUID correlation) {
        return execute(envelope, configuration, transport, transport.accepted(), correlation);
    }

    static long execute(Path envelopePath, Path configurationPath, ChatCompletionsTransport transport,
            ChatCompletionsTransport.Deadline deadline, UUID correlation) {
        return execute(envelopePath, configurationPath, transport, deadline, correlation, Audience.RUN);
    }

    static long executeManagement(Path envelopePath, Path configurationPath, ChatCompletionsTransport transport,
            UUID correlation) {
        return execute(envelopePath, configurationPath, transport, transport.accepted(), correlation,
                Audience.MANAGEMENT);
    }

    static long execute(Path envelopePath, Path configurationPath, ChatCompletionsTransport transport,
            ChatCompletionsTransport.Deadline deadline, UUID correlation, Audience audience) {
        try (var operation = transport.admit(deadline)) {
            operation.remaining();
            var configuration = GatewayRunConfiguration.read(configurationPath);
            var decoded = new ProtocolCodec().readDispatch(GatewayRunConfiguration.snapshot(envelopePath, 4096));
            if (!audience.accepts(decoded)) {
                throw GatewayRunWire.invalid();
            }
            DispatchEnvelope envelope = decoded;
            operation.remaining();
            var core = new CoreRunClient(configuration, audience);
            var consumed = core.consume(envelope, correlation, operation);
            byte[] response = null;
            byte[] outcome = null;
            try {
                try {
                    operation.remaining();
                    configuration.verify(consumed);
                    String bearer = configuration.credential(consumed);
                    operation.remaining();
                    response = GatewayRunWire
                            .safeResponse(operation
                                    .postWithin(configuration.provider(consumed), consumed.payload(),
                                            envelope.payloadSha256(), bearer),
                                    bearer);
                } catch (GatewayFailure unknown) {
                    response = null;
                }
                operation.remaining();
                outcome = GatewayRunWire.outcome(envelope, correlation, response);
                long version = core.report(envelope, correlation, outcome, operation);
                if (response == null) {
                    throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
                }
                operation.remaining();
                return version;
            } finally {
                if (response != null) {
                    Arrays.fill(response, (byte) 0);
                }
                if (outcome != null) {
                    Arrays.fill(outcome, (byte) 0);
                }
            }
        } catch (Exception unavailable) {
            throw new GatewayFailure(GatewayFailure.Code.UPSTREAM_FAILURE);
        }
    }
}
