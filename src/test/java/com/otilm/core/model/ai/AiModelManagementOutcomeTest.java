package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiModelManagementOutcome.Receipt;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiModelManagementOutcomeTest {
    @ParameterizedTest
    @ValueSource(strings = {"intent", "correlation", "null-sha", "short-sha", "upper-sha", "zero", "negative"})
    void acknowledgementCannotRepresentMissingIdentityNonCanonicalDigestOrNonPositiveStoredVersion(String invalid) {
        UUID intent = invalid.equals("intent") ? null : UUID.randomUUID();
        UUID correlation = invalid.equals("correlation") ? null : UUID.randomUUID();
        String sha = switch (invalid) {
            case "null-sha" -> null;
            case "short-sha" -> "a";
            case "upper-sha" -> "A".repeat(64);
            default -> "a".repeat(64);
        };
        long version = invalid.equals("zero") ? 0 : invalid.equals("negative") ? -1 : 1;
        assertThatThrownBy(() -> new Receipt(intent, correlation, sha, version))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void protectedResultAndReceiptToStringNeverExposeActorContentOrProviderMetadata() {
        var receipt = new Receipt(UUID.randomUUID(), UUID.randomUUID(), "a".repeat(64), 1);
        var result = new Result(receipt, "TEXT", "SYNTHETIC_TEXT_CANARY", "STOP", 1L, 1L, 2L);
        assertThat(result.toString()).doesNotContain("SYNTHETIC_TEXT_CANARY", receipt.outcomeSha256());
        assertThat(receipt.toString()).doesNotContain(receipt.intentId().toString(), receipt.outcomeSha256());
        assertThat(result.receipt()).isEqualTo(receipt);
        assertThat(result.promptTokens()).isEqualTo(1);
    }
}
