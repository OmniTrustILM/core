package com.otilm.core.dao.converter;

import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** Stores a discovery run's delivery mode as its wire code, the value the connector contract names it by. */
@Converter
public class DiscoveryDeliveryModeConverter implements AttributeConverter<DiscoveryDeliveryMode, String> {

    @Override
    public String convertToDatabaseColumn(DiscoveryDeliveryMode mode) {
        return mode == null ? null : mode.getCode();
    }

    @Override
    public DiscoveryDeliveryMode convertToEntityAttribute(String code) {
        return code == null ? null : DiscoveryDeliveryMode.findByCode(code);
    }
}
