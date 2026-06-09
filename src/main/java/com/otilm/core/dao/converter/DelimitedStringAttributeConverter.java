package com.otilm.core.dao.converter;

import jakarta.persistence.AttributeConverter;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public abstract class DelimitedStringAttributeConverter<T> implements AttributeConverter<List<T>, String> {

    private final String delimiter;

    protected DelimitedStringAttributeConverter(String delimiter) {
        this.delimiter = delimiter;
    }

    protected abstract T convertToEntityAttributeElement(String stringElement);

    protected abstract String convertToDatabaseColumnElement(T attributeElement);

    @Override
    public String convertToDatabaseColumn(List<T> elements) {
        if (elements == null) {
            return null;
        }
        if (elements.isEmpty()) {
            return "";
        }
        return elements.stream()
                .map(this::convertToDatabaseColumnElement)
                .collect(Collectors.joining(delimiter));
    }

    @Override
    public List<T> convertToEntityAttribute(String delimitedString) {
        if (delimitedString == null) {
            return null;
        }
        if (delimitedString.isEmpty()) {
            return List.of();
        }

        return Arrays.stream(delimitedString.split(delimiter))
                .map(this::convertToEntityAttributeElement)
                .toList();
    }
}
