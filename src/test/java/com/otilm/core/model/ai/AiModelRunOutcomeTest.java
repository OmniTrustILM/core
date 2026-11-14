package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult;
import com.otilm.core.model.ai.AiModelRunOutcome.Receipt;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiModelRunOutcomeTest {
    private static final UUID INTENT = UUID.randomUUID();
    private static final UUID CORRELATION = UUID.randomUUID();
    private static final String SHA = "a".repeat(64);
    private static final String BAD_SHA = "A".repeat(64);

    @Test
    void storedReceiptIsMetadataOnlyAndRedacted() {
        var receipt = new Receipt(INTENT, CORRELATION, SHA, 7);
        assertThat(receipt.intentId()).isEqualTo(INTENT);
        assertThat(receipt.gatewayCorrelation()).isEqualTo(CORRELATION);
        assertThat(receipt.outcomeSha256()).isEqualTo(SHA);
        assertThat(receipt.resultVersion()).isEqualTo(7);
        assertThat(receipt.toString()).doesNotContain(INTENT.toString(), CORRELATION.toString(), SHA);
        assertThatThrownBy(() -> new Receipt(null, CORRELATION, SHA, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Receipt(INTENT, null, SHA, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Receipt(INTENT, CORRELATION, null, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Receipt(INTENT, CORRELATION, BAD_SHA, 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void databaseVersionMustBePositive(long version) {
        assertThatThrownBy(() -> new Receipt(INTENT, CORRELATION, SHA, version))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void preservesOnlyActualServerValidationWithoutManufacturingUsage() {
        byte[] known = "{\"model\":\"lab\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"content\":\"MODEL_CONTENT_CANARY\"}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}"
                .getBytes(StandardCharsets.UTF_8);
        var derived = DerivedResult.from(AiModelRunResult.validate(known, "lab", 32));
        assertThat(derived.code()).isEqualTo("TEXT");
        assertThat(derived.finish()).isEqualTo("STOP");
        assertThat(derived.text()).isEqualTo("MODEL_CONTENT_CANARY");
        assertThat(derived.promptTokens()).isEqualTo(1);
        assertThat(derived.completionTokens()).isEqualTo(2);
        assertThat(derived.totalTokens()).isEqualTo(3);
        assertThat(derived.toString()).doesNotContain("MODEL_CONTENT_CANARY");
        var unknown = DerivedResult.from(AiModelRunResult.validate(null, "lab", 32));
        assertThat(unknown.code()).isEqualTo("INVALID");
        assertThat(unknown.text()).isNull();
        assertThat(unknown.finish()).isNull();
        assertThat(unknown.promptTokens()).isNull();
        assertThat(unknown.completionTokens()).isNull();
        assertThat(unknown.totalTokens()).isNull();
    }
}
