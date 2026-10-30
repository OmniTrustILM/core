package com.otilm.core.model.cbom;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.LinkedHashMap;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@Schema(description = "Response containing (C)BOM")
@JsonIgnoreProperties(ignoreUnknown = true)
public class BomResponseDto extends LinkedHashMap<String, Object> {

    private static final String FIELD_SPEC_VERSION = "specVersion";
    private static final String FIELD_SERIAL_NUMBER = "serialNumber";
    private static final String FIELD_VERSION = "version";

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append(FIELD_SPEC_VERSION, get(FIELD_SPEC_VERSION))
                .append(FIELD_SERIAL_NUMBER, get(FIELD_SERIAL_NUMBER))
                .append(FIELD_VERSION, get(FIELD_VERSION))
                .toString();
    }
}
