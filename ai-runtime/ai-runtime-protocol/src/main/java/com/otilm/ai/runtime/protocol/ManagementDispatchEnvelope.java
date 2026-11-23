package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.UUID;

@JsonPropertyOrder({"protocolVersion", "intentId", "payloadSha256", "binding"})
public record ManagementDispatchEnvelope(int protocolVersion, UUID intentId, String payloadSha256,
        ManagementBinding binding) implements DispatchEnvelope {
    public ManagementDispatchEnvelope {
        ProtocolValidation.envelope(protocolVersion, intentId, payloadSha256, binding);
    }
}
