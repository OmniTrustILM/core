package com.otilm.core.model.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class KeyTransferTest {

    @ParameterizedTest
    @CsvSource({"IMPORT, import", "EXPORT, export"})
    void toString_isTheDirectionAsAWord(KeyTransfer direction, String word) {
        // when
        String written = direction.toString();

        // then
        assertThat(written).isEqualTo(word);
    }
}
