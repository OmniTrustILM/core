package com.otilm.core.dao.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.time.Duration;

/** Stores a duration as ISO-8601 text, the form the API accepts and publishes it in. */
@Converter
public class DurationIsoConverter implements AttributeConverter<Duration, String> {

    @Override
    public String convertToDatabaseColumn(Duration duration) {
        return duration == null ? null : duration.toString();
    }

    @Override
    public Duration convertToEntityAttribute(String iso) {
        return iso == null ? null : Duration.parse(iso);
    }
}
