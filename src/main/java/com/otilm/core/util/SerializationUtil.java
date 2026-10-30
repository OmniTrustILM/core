package com.otilm.core.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.acme.Identifier;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.List;

public class SerializationUtil {
    private static final ObjectMapper OBJECT_MAPPER = ObjectMapperFactory.emptyBeanTolerantStorage();

    public static String serializeIdentifiers(List<Identifier> identifiers) {
        try {
            return OBJECT_MAPPER.writeValueAsString(identifiers);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static List<Identifier> deserializeIdentifiers(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            return OBJECT_MAPPER.readValue(identifier, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Identifier deserializeIdentifier(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(identifier, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String serialize(Object object) {
        try {
            return OBJECT_MAPPER.writeValueAsString(object);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Object deserialize(String object, Class returnType) {
        if (object == null || object.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            return OBJECT_MAPPER.readValue(object, returnType);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static <T> T convertValue(Object source, Class<T> returnType) {
        if (source == null) {
            return null;
        }
        return OBJECT_MAPPER.convertValue(source, returnType);
    }

}
