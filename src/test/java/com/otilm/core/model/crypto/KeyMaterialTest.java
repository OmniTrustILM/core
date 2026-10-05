package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KeyMaterialTest {

    private static final String SERIALIZED_VALUE = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";

    @Test
    void toString_leavesTheValueOut() {
        // given
        KeyMaterial material = new KeyMaterial(KeyFormat.PRKI, SERIALIZED_VALUE);

        // when
        String text = material.toString();

        // then
        assertThat(text).contains("PRKI").doesNotContain(SERIALIZED_VALUE);
    }

    @Test
    void toString_ofProviderKeyItem_leavesTheValueOut_andKeepsTheName() {
        // given
        ProviderKeyItem item = new ProviderKeyItem("test-key", KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048, null,
                new KeyMaterial(KeyFormat.PRKI, SERIALIZED_VALUE), List.of(), null);

        // when
        String text = item.toString();

        // then
        assertThat(text).contains("test-key").doesNotContain(SERIALIZED_VALUE);
    }
}
