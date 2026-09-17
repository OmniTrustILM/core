package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RemoteKeyReferenceIdentifierTest {

    @Test
    void toIdentifierString_returnsUuid_forUuidReference() {
        // given
        UUID uuid = UUID.randomUUID();
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(uuid);

        // when
        String identifier = reference.toIdentifierString();

        // then
        assertEquals(uuid.toString(), identifier);
    }

    @Test
    void toIdentifierString_prefixesFormattedMetadata() {
        // given
        String attributeName = "alias";
        String keyAlias = "signing-key";
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(attributeName);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(keyAlias)));
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(List.of(attribute));

        // when
        String identifier = reference.toIdentifierString();

        // then
        assertEquals("key metadata reference {alias=[signing-key]}", identifier);
    }
}
