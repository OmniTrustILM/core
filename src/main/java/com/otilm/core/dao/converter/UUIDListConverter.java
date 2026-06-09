package com.otilm.core.dao.converter;

import java.util.UUID;

public class UUIDListConverter extends DelimitedStringAttributeConverter<UUID> {

    public UUIDListConverter() {
        super(";");
    }

    @Override
    protected UUID convertToEntityAttributeElement(String stringElement) {
        return UUID.fromString(stringElement);
    }

    @Override
    protected String convertToDatabaseColumnElement(UUID attributeElement) {
        return attributeElement.toString();
    }
}
