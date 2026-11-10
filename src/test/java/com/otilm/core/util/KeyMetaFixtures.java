package com.otilm.core.util;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import java.util.List;

/** Connector metadata that identifies a key on its token by a key ID, as a PKCS#11 provider reports it. */
public final class KeyMetaFixtures {

    private static final String KEY_ID_ATTRIBUTE_UUID = "6b1c9c5e-2f8a-4a7e-9f2d-5b8e1c3a7d40";

    private KeyMetaFixtures() {
    }

    public static List<MetadataAttribute> keyIdMeta(String keyId) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(KEY_ID_ATTRIBUTE_UUID);
        attribute.setName("keyId");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(new MetadataAttributeProperties());
        attribute.setContent(List.of(new StringAttributeContentV3(keyId)));
        return List.of(attribute);
    }
}
