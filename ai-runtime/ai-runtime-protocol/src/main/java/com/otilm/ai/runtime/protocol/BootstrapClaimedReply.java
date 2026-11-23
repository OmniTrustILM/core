package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.time.Instant;

@JsonPropertyOrder({"protocolVersion", "binding", "leaseExpiresAt"})
public record BootstrapClaimedReply(int protocolVersion, ClaimBinding binding,
        Instant leaseExpiresAt) implements BootstrapReply {
    public BootstrapClaimedReply {
        ProtocolValidation.message(protocolVersion, binding, leaseExpiresAt);
    }
}
