package com.otilm.core.dao.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.io.Serializable;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;

@Converter
public class ObjectToJsonConverter implements AttributeConverter<Object, String> {

    @Autowired
    ObjectMapper objectMapper;

    @SneakyThrows
    @Override
    public String convertToDatabaseColumn(Object value) {
        return value == null ? null : objectMapper.writeValueAsString(value);
    }

    @SneakyThrows
    @Override
    public Object convertToEntityAttribute(String json) {
        return json == null ? null : objectMapper.readValue(json, Serializable.class);
    }
}
