package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.time.Instant;

@JsonPropertyOrder({"protocolVersion", "binding", "sequence", "leaseExpiresAt"})
public record ClaimHeartbeatReply(int protocolVersion, ClaimBinding binding, long sequence, Instant leaseExpiresAt) {
    public ClaimHeartbeatReply {
        ProtocolValidation.message(protocolVersion, binding, leaseExpiresAt);
        ProtocolValidation.positive(sequence, ProtocolException.Reason.INVALID_MESSAGE);
    }
}
