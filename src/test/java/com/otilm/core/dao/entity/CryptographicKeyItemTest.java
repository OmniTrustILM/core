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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static org.assertj.core.api.Assertions.assertThat;

class CryptographicKeyItemTest {

    @Test
    void publicMappings_preserveAbsentLength_forPqcItem() {
        // given
        CryptographicKeyItem item = keyItem(KeyAlgorithm.MLDSA, KeyType.PRIVATE_KEY, null);

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(item);
        CryptographicKeyFullModel model = aKeySnapshot().withItems(List.of(snapshot)).build();

        // then
        assertThat(item.mapToDto().getLength()).isNull();
        assertThat(item.mapToListDto().getLength()).isNull();
        assertThat(snapshot.length()).isNull();
        assertThat(CryptographicKeyDtoMapper.mapItemToDetailDto(snapshot).getLength()).isNull();
        assertThat(CryptographicKeyDtoMapper.getKeyItemsSummary(model).getFirst().getLength()).isNull();
    }

    @Test
    void carriesTheParameterSet_whenMappedToAnyResponse() {
        // given
        CryptographicKeyItem item = keyItem(KeyAlgorithm.MLDSA, KeyType.PRIVATE_KEY, null);
        item.setParameterSet("ML-DSA-65");

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(item);
        CryptographicKeyFullModel model = aKeySnapshot().withItems(List.of(snapshot)).build();

        // then
        assertThat(item.mapToDto().getParameterSet()).isEqualTo("ML-DSA-65");
        assertThat(item.mapToListDto().getParameterSet()).isEqualTo("ML-DSA-65");
        assertThat(CryptographicKeyDtoMapper.mapItemToDetailDto(snapshot).getParameterSet()).isEqualTo("ML-DSA-65");
        assertThat(CryptographicKeyDtoMapper.getKeyItemsSummary(model).getFirst().getParameterSet())
                .isEqualTo("ML-DSA-65");
    }

    @Test
    void reportsTheCustomFormat_whenTheConnectorReportedNone() {
        // given
        CryptographicKeyItem item = keyItem(KeyAlgorithm.RSA, KeyType.PRIVATE_KEY, 2048);

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(item);
        CryptographicKeyFullModel model = aKeySnapshot().withItems(List.of(snapshot)).build();

        // then
        assertThat(item.mapToDto().getFormat()).isEqualTo(KeyFormat.CUSTOM);
        assertThat(item.mapToListDto().getFormat()).isEqualTo(KeyFormat.CUSTOM);
        assertThat(CryptographicKeyDtoMapper.mapItemToDetailDto(snapshot).getFormat()).isEqualTo(KeyFormat.CUSTOM);
        assertThat(CryptographicKeyDtoMapper.getKeyItemsSummary(model).getFirst().getFormat())
                .isEqualTo(KeyFormat.CUSTOM);
    }

    @Test
    void keepsTheReportedFormat_whenTheConnectorReportedOne() {
        // given
        CryptographicKeyItem item = keyItem(KeyAlgorithm.RSA, KeyType.PUBLIC_KEY, 2048);
        item.setFormat(KeyFormat.SPKI);

        // when
        KeyFormat detailFormat = item.mapToDto().getFormat();
        KeyFormat listFormat = item.mapToListDto().getFormat();

        // then
        assertThat(detailFormat).isEqualTo(KeyFormat.SPKI);
        assertThat(listFormat).isEqualTo(KeyFormat.SPKI);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0})
    void setLength_storesNull_forLengthBelowOne(int lengthBelowOne) {
        // given
        CryptographicKeyItem item = keyItem(KeyAlgorithm.UNKNOWN, KeyType.PUBLIC_KEY, null);

        // when
        item.setLength(lengthBelowOne);

        // then
        assertThat(item.getLength()).isNull();
        assertThat(CryptographicKeyItemBasicModel.from(item).length()).isNull();
    }

    private static CryptographicKeyItem keyItem(KeyAlgorithm algorithm, KeyType type, Integer length) {
        CryptographicKey wrapper = new CryptographicKey();
        wrapper.setUuid(UUID.randomUUID());
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(UUID.randomUUID());
        item.setKey(wrapper);
        item.setKeyAlgorithm(algorithm);
        item.setType(type);
        item.setLength(length);
        return item;
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
