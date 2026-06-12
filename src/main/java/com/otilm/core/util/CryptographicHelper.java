package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.connector.cryptography.key.value.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.Map;

public class CryptographicHelper {

    private CryptographicHelper() {}

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);


    public static String serializeKeyValue(KeyFormat keyFormat, KeyValue value) {
        if (value == null || keyFormat == null) return null;
        switch (keyFormat) {
            case RAW:
                return OBJECT_MAPPER.convertValue(value, RawKeyValue.class).getValue();
            case SPKI:
                return OBJECT_MAPPER.convertValue(value, SpkiKeyValue.class).getValue();
            case PRKI:
                return OBJECT_MAPPER.convertValue(value, PrkiKeyValue.class).getValue();
            case EPRKI:
                return OBJECT_MAPPER.convertValue(value, EprkiKeyValue.class).getValue();
            case CUSTOM:
                try {
                    return serializeCustomKeyValue(OBJECT_MAPPER.convertValue(value, CustomKeyValue.class).getValues());
                } catch (JsonProcessingException e) {
                    throw new ValidationException(
                            ValidationError.create(
                                    "Unable to read the json"
                            )
                    );
                }
            default:
                throw new ValidationException(
                        ValidationError.create(
                                "Unrecognized Key Format"
                        )
                );
        }
    }

    public static String serializeCustomKeyValue(Map<String, String> customKeyValue) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(customKeyValue);
    }
}
