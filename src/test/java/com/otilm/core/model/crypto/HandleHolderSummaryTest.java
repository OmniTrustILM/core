package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;
import static org.assertj.core.api.Assertions.assertThat;

class HandleHolderSummaryTest {

    @Test
    void agrees_whenTheTokenListsThePrivateKeyWithAnUnknownAlgorithm() {
        // given
        HandleHolderSummary holder = holdKeyOf(KeyAlgorithm.ECDSA);
        ProviderKeyItem unknownAlgorithm = aProviderKeyItem().withAlgorithm(KeyAlgorithm.UNKNOWN).build();

        // when
        boolean agrees = holder.agreesWith(unknownAlgorithm, null);

        // then
        assertThat(agrees).isTrue();
    }

    @Test
    void agrees_whenTheHoldingKeyHasAnUnknownAlgorithm() {
        // given
        HandleHolderSummary unknownAlgorithm = holdKeyOf(KeyAlgorithm.UNKNOWN);
        ProviderKeyItem listed = aProviderKeyItem().withAlgorithm(KeyAlgorithm.ECDSA).build();

        // when
        boolean agrees = unknownAlgorithm.agreesWith(listed, null);

        // then
        assertThat(agrees).isTrue();
    }

    @Test
    void disagrees_whenBothAlgorithmsAreKnownAndDiffer() {
        // given
        HandleHolderSummary holder = holdKeyOf(KeyAlgorithm.ECDSA);
        ProviderKeyItem anotherAlgorithm = aProviderKeyItem().withAlgorithm(KeyAlgorithm.RSA).build();

        // when
        boolean agrees = holder.agreesWith(anotherAlgorithm, null);

        // then
        assertThat(agrees).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static HandleHolderSummary holdKeyOf(KeyAlgorithm algorithm) {
        return new HandleHolderSummary(UUID.randomUUID(), "holder", UUID.randomUUID(), algorithm, null, null, null,
                true);
    }
}
