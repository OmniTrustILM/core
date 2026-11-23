package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.UUID;

@JsonPropertyOrder({"runId", "attemptId", "podUid", "claimId", "fence"})
public record ClaimBinding(UUID runId, UUID attemptId, UUID podUid, UUID claimId, long fence) {
    public ClaimBinding {
        ProtocolValidation.required(ProtocolException.Reason.INVALID_MESSAGE, runId, attemptId, podUid, claimId);
        ProtocolValidation.positive(fence, ProtocolException.Reason.INVALID_MESSAGE);
    }
}
