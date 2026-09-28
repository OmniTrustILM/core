package com.otilm.core.dao.entity;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptographicKeyItemTest {

    private static final String KEY_DATA = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";

    @Test
    void toString_leavesTheKeyDataOut() {
        // given
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setName("signing key");
        item.setType(KeyType.PRIVATE_KEY);
        item.setFormat(KeyFormat.PRKI);
        item.setKeyData(KEY_DATA);

        // when
        String text = item.toString();

        // then
        assertThat(text).contains("signing key").doesNotContain(KEY_DATA);
    }
}
