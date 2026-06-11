package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;

import java.util.List;
import java.util.UUID;

public class RequestAttributeV3Builder {

    private UUID uuid;
    private String name;
    private AttributeContentType contentType = AttributeContentType.STRING;
    private String stringValue;

    public static RequestAttributeV3Builder aCustomAttribute() {
        return new RequestAttributeV3Builder();
    }

    public RequestAttributeV3Builder withUuid(String uuid) {
        this.uuid = UUID.fromString(uuid);
        return this;
    }

    public RequestAttributeV3Builder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public RequestAttributeV3Builder withName(String name) {
        this.name = name;
        return this;
    }

    public RequestAttributeV3Builder withStringContent(String value) {
        this.contentType = AttributeContentType.STRING;
        this.stringValue = value;
        return this;
    }

    public RequestAttributeV3 build() {
        return new RequestAttributeV3(uuid, name, contentType,
                List.of(new StringAttributeContentV3(stringValue)));
    }
}
