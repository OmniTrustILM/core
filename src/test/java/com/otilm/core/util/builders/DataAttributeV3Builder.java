package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import java.util.UUID;

/** Builds valid v3 data-attribute definitions for integration tests. */
public final class DataAttributeV3Builder {

    private UUID uuid = UUID.randomUUID();
    private String name = "test-token-attribute";

    public static DataAttributeV3Builder aDataAttribute() {
        return new DataAttributeV3Builder();
    }

    public DataAttributeV3Builder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public DataAttributeV3Builder withName(String name) {
        this.name = name;
        return this;
    }

    public DataAttributeV3 build() {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(uuid.toString());
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        attribute.setProperties(properties);
        return attribute;
    }
}
