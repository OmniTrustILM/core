package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.time.Instant;
import java.util.UUID;

@JsonPropertyOrder({"actorId", "sessionId", "configurationId", "configurationRevision", "action", "expiresAt"})
public record ManagementBinding(UUID actorId, UUID sessionId, UUID configurationId, long configurationRevision,
        ManagementAction action, Instant expiresAt) {
    public ManagementBinding {
        ProtocolValidation.required(actorId, sessionId, configurationId, action, expiresAt);
        ProtocolValidation.positive(configurationRevision);
    }
}
