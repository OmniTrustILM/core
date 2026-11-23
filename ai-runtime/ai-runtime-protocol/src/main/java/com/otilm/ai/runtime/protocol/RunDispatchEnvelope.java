package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.UUID;

@JsonPropertyOrder({"protocolVersion", "intentId", "payloadSha256", "binding"})
public record RunDispatchEnvelope(int protocolVersion, UUID intentId, String payloadSha256,
        RunBinding binding) implements DispatchEnvelope {
    public RunDispatchEnvelope {
        ProtocolValidation.envelope(protocolVersion, intentId, payloadSha256, binding);
    }
}
