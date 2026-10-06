package com.otilm.core.dao.entity;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.mapper.crypto.CryptographicKeyDtoMapper;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static org.assertj.core.api.Assertions.assertThat;

class CryptographicKeyItemTest {

    @Test
    void publicMappings_preserveAbsentLength_forPqcItem() {
        // given
        CryptographicKey wrapper = new CryptographicKey();
        wrapper.setUuid(UUID.randomUUID());
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(UUID.randomUUID());
        item.setKey(wrapper);
        item.setKeyAlgorithm(KeyAlgorithm.MLDSA);
        item.setType(KeyType.PRIVATE_KEY);
        item.setLength(null);

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(item);
        CryptographicKeyFullModel model = aKeySnapshot().withItems(List.of(snapshot)).build();

        // then
        assertThat(item.mapToDto().getLength()).isNull();
        assertThat(item.mapToSummaryDto().getLength()).isNull();
        assertThat(snapshot.length()).isNull();
        assertThat(CryptographicKeyDtoMapper.mapItemToDetailDto(snapshot).getLength()).isNull();
        assertThat(CryptographicKeyDtoMapper.getKeyItemsSummary(model).getFirst().getLength()).isNull();
    }

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
