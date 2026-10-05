package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptographicKeyItemBasicModelTest {

    private static final String KEY_DATA = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";

    @Test
    void toString_leavesTheKeyDataOut() {
        // given
        UUID uuid = UUID.randomUUID();
        CryptographicKeyItemBasicModel model = new CryptographicKeyItemBasicModel(uuid, UUID.randomUUID(), "test-key",
                new RemoteKeyReference.UuidReference(UUID.randomUUID()), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA,
                KeyFormat.PRKI, KEY_DATA, 2048, KeyState.ACTIVE, true, List.of(), null, null, false);

        // when
        String text = model.toString();

        // then
        assertThat(text).contains(uuid.toString()).doesNotContain(KEY_DATA);
    }
}
