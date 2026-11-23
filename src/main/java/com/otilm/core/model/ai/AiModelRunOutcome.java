package com.otilm.core.model.ai;

import java.util.Objects;
import java.util.UUID;

/** Immutable storage values only; no sender, dispatch, result-reader or completion authority. */
public final class AiModelRunOutcome {
    private AiModelRunOutcome() {
    }

    public record Receipt(UUID intentId, UUID gatewayCorrelation, String outcomeSha256, long resultVersion) {
        public Receipt {
            if (intentId == null || gatewayCorrelation == null || outcomeSha256 == null
                    || !outcomeSha256.matches("[0-9a-f]{64}") || resultVersion <= 0) {
                throw new IllegalArgumentException("Invalid model outcome receipt");
            }
        }

        @Override
        public String toString() {
            return "ModelOutcomeReceipt[redacted]";
        }
    }

    /** Server-derived validation columns. The public writer never accepts this as an input. */
    public record DerivedResult(String code, String text, String finish, Long promptTokens, Long completionTokens,
            Long totalTokens) {
        public static DerivedResult from(AiModelRunResult.Validation validation) {
            Objects.requireNonNull(validation);
            var usage = validation.usage().orElse(null);
            return new DerivedResult(validation.code().name(), validation.text(),
                    validation.finish() == null ? null : validation.finish().name(),
                    usage == null ? null : usage.promptTokens(), usage == null ? null : usage.completionTokens(),
                    usage == null ? null : usage.totalTokens());
        }

        @Override
        public String toString() {
            return "DerivedModelOutcome[redacted]";
        }
    }
}
