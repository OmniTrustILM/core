package com.otilm.core.model.ai;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Immutable Core-authored input for one execution; construction grants no caller or model authority. */
public record AiModelRunInput(UUID runId, UUID raProfileUuid, Set<UUID> certificateUuids, String instructions,
        String prompt, int outputTokens) {
    public AiModelRunInput {
        Objects.requireNonNull(runId);
        Objects.requireNonNull(raProfileUuid);
        certificateUuids = Set.copyOf(certificateUuids);
        if (certificateUuids.size() > 100) {
            throw new IllegalArgumentException("Certificate scope exceeds the read limit");
        }
        AiModelDispatchPayload.text("stored-input", outputTokens, instructions, prompt, "");
    }

    @Override
    public String toString() {
        return "AiModelRunInput[redacted]";
    }
}
