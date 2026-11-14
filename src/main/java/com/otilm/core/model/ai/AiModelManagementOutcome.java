package com.otilm.core.model.ai;

import java.util.UUID;

public final class AiModelManagementOutcome {
    private AiModelManagementOutcome() {
    }

    public record Receipt(UUID intentId, UUID gatewayCorrelation, String outcomeSha256, long resultVersion) {
        public Receipt {
            if (intentId == null || gatewayCorrelation == null || outcomeSha256 == null
                    || !outcomeSha256.matches("[0-9a-f]{64}") || resultVersion < 1) {
                throw new IllegalArgumentException("Invalid management outcome receipt");
            }
        }

        @Override
        public String toString() {
            return "ManagementOutcomeReceipt[redacted]";
        }
    }

    public record Result(Receipt receipt, String code, String text, String finish, Long promptTokens,
            Long completionTokens, Long totalTokens) {
        @Override
        public String toString() {
            return "ManagementResult[redacted]";
        }
    }
}
