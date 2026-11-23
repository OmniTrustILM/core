package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiModelManagementOutcome.Receipt;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiModelManagementOutcomeTest {
    private static final String SYNTHETIC_TEXT_CANARY = "SYNTHETIC_TEXT_CANARY";

    @ParameterizedTest
    @ValueSource(strings = {"intent", "correlation", "null-sha", "short-sha", "upper-sha", "zero", "negative"})
    void throwsIllegalArgument_whenReceiptFieldsAreInvalid(String invalid) {
        // given
        UUID intent = invalid.equals("intent") ? null : UUID.randomUUID();
        UUID correlation = invalid.equals("correlation") ? null : UUID.randomUUID();
        String sha = switch (invalid) {
            case "null-sha" -> null;
            case "short-sha" -> "a";
            case "upper-sha" -> "A".repeat(64);
            default -> "a".repeat(64);
        };
        long version = invalid.equals("zero") ? 0 : invalid.equals("negative") ? -1 : 1;

        // when
        ThrowingCallable createReceipt = () -> new Receipt(intent, correlation, sha, version);

        // then
        assertThatThrownBy(createReceipt).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void hidesIntentAndDigest_whenReceiptIsRenderedAsText() {
        // given
        var receipt = aReceipt();

        // when
        String rendered = receipt.toString();

        // then
        assertThat(rendered).doesNotContain(receipt.intentId().toString(), receipt.outcomeSha256());
    }

    @Test
    void hidesContentAndDigest_whenResultIsRenderedAsText() {
        // given
        var receipt = aReceipt();
        var result = aResult(receipt);

        // when
        String rendered = result.toString();

        // then
        assertThat(rendered).doesNotContain(SYNTHETIC_TEXT_CANARY, receipt.outcomeSha256());
    }

    @Test
    void exposesReceiptAndTokenCount_whenReadingResultAccessors() {
        // given
        var receipt = aReceipt();
        var result = aResult(receipt);

        // when
        Receipt exposedReceipt = result.receipt();
        long promptTokens = result.promptTokens();

        // then
        assertThat(exposedReceipt).isEqualTo(receipt);
        assertThat(promptTokens).isEqualTo(1);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Receipt aReceipt() {
        return new Receipt(UUID.randomUUID(), UUID.randomUUID(), "a".repeat(64), 1);
    }

    private static Result aResult(Receipt receipt) {
        return new Result(receipt, "TEXT", SYNTHETIC_TEXT_CANARY, "STOP", 1L, 1L, 2L);
    }
}
