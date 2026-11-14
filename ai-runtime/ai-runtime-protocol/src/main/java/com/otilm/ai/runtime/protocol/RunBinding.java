package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.time.Instant;
import java.util.UUID;

@JsonPropertyOrder({"runId", "attemptId", "podUid", "claimId", "fence", "expiresAt"})
public record RunBinding(UUID runId, UUID attemptId, UUID podUid, UUID claimId, long fence, Instant expiresAt) {
    public RunBinding {
        ProtocolValidation.required(runId, attemptId, podUid, claimId, expiresAt);
        ProtocolValidation.positive(fence);
    }
}
