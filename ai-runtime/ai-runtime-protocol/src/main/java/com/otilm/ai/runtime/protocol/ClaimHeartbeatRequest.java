package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"protocolVersion", "binding", "sequence"})
public record ClaimHeartbeatRequest(int protocolVersion, ClaimBinding binding, long sequence) {
    public ClaimHeartbeatRequest {
        ProtocolValidation.message(protocolVersion, binding);
        ProtocolValidation.positive(sequence, ProtocolException.Reason.INVALID_MESSAGE);
    }
}
