package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.UUID;

@JsonPropertyOrder({"protocolVersion", "code", "correlationId"})
public record RuntimeErrorReply(int protocolVersion, RuntimeErrorCode code, UUID correlationId) {
    public RuntimeErrorReply {
        ProtocolValidation.message(protocolVersion, code, correlationId);
    }
}
