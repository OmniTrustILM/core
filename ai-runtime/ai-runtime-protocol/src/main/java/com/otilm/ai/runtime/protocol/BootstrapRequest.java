package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.UUID;

@JsonPropertyOrder({"protocolVersion", "runId", "attemptId", "podUid"})
public record BootstrapRequest(int protocolVersion, UUID runId, UUID attemptId, UUID podUid) {
    public BootstrapRequest {
        ProtocolValidation.message(protocolVersion, runId, attemptId, podUid);
    }
}
