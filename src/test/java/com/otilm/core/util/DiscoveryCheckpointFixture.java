package com.otilm.core.util;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import java.util.List;
import java.util.UUID;

/**
 * Builds the connector run handle stored in {@code discovery.checkpoint}. Every field the attribute deserializer reads
 * is set: {@code type} and {@code version} select the concrete class, so a handle missing either does not survive the
 * round trip through the JSONB column.
 */
public final class DiscoveryCheckpointFixture {

    private DiscoveryCheckpointFixture() {
    }

    public static List<MetadataAttribute> checkpoint(String name, String value) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return List.of(attribute);
    }
}
