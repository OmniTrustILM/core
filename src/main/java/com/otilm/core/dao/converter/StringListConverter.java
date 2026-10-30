package com.otilm.core.dao.converter;

public class StringListConverter extends DelimitedStringAttributeConverter<String> {

    public StringListConverter() {
        super(";");
    }

    @Override
    protected String convertToEntityAttributeElement(String stringElement) {
        return stringElement;
    }

    @Override
    protected String convertToDatabaseColumnElement(String attributeElement) {
        return attributeElement;
    }
}
