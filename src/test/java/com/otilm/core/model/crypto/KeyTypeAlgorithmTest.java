package com.otilm.core.model.crypto;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyTypeAlgorithmTest {

    @Test
    void parse_readsATypeAndAnAlgorithmCode() {
        assertThat(KeyTypeAlgorithm.parse("keyPair:ML-DSA"))
                .isEqualTo(new KeyTypeAlgorithm(KeyRequestType.KEY_PAIR, KeyAlgorithm.MLDSA));
    }

    @ParameterizedTest
    @ValueSource(strings = {"keyPair", "keyPair:", ":RSA", "keyPair:RSA:extra", "pair:RSA", "keyPair:RSB"})
    void parse_refusesAnythingElse(String value) {
        assertThrows(ValidationException.class, () -> KeyTypeAlgorithm.parse(value));
    }
}
