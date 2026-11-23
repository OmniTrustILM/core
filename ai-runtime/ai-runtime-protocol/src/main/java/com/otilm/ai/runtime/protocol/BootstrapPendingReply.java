package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"protocolVersion", "retryAfterMillis"})
public record BootstrapPendingReply(int protocolVersion, int retryAfterMillis) implements BootstrapReply {
    public BootstrapPendingReply {
        ProtocolValidation.message(protocolVersion);
        if (retryAfterMillis < 100 || retryAfterMillis > 1000) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
    }
}
