package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairMetaMatcher;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyPairHandlesTest {

    private static List<MetadataAttribute> handle(String keyId) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid("6b1c9c5e-2f8a-4a7e-9f2d-5b8e1c3a7d40");
        attribute.setName("keyId");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(new MetadataAttributeProperties());
        attribute.setContent(List.of(new StringAttributeContentV3(keyId)));
        return List.of(attribute);
    }

    @Test
    void decodesWhatItEncoded() {
        // given
        List<MetadataAttribute> keyPairMeta = handle("0a0b");

        // when
        String encoded = KeyPairHandles.encode(keyPairMeta);
        List<MetadataAttribute> decoded = KeyPairHandles.decode(encoded);

        // then
        assertThat(encoded).matches("[A-Za-z0-9_-]+");
        assertThat(KeyPairMetaMatcher.matches(keyPairMeta, decoded)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"not base64!", "e30", "W10"})
    void refusesAMalformedString(String keyPairHandle) {
        // when / then
        assertThatThrownBy(() -> KeyPairHandles.decode(keyPairHandle))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not decode to the metadata of a key pair");
    }

    @Test
    void refusesAHandleWithoutContent() {
        // given
        List<MetadataAttribute> withoutContent = handle("0a0b");
        withoutContent.getFirst().setContent(null);
        String encoded = KeyPairHandles.encode(withoutContent);

        // when / then
        assertThatThrownBy(() -> KeyPairHandles.decode(encoded))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not decode to the metadata of a key pair");
    }
}
