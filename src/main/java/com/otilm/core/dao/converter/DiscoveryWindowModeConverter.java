package com.otilm.core.dao.converter;

import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** Stores a discovery run's window mode as its wire code, the value the API names it by. */
@Converter
public class DiscoveryWindowModeConverter implements AttributeConverter<DiscoveryWindowMode, String> {

    @Override
    public String convertToDatabaseColumn(DiscoveryWindowMode mode) {
        return mode == null ? null : mode.getCode();
    }

    @Override
    public DiscoveryWindowMode convertToEntityAttribute(String code) {
        return code == null ? null : DiscoveryWindowMode.findByCode(code);
    }
}
