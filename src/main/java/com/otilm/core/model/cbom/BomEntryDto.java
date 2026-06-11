package com.otilm.core.model.cbom;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import jakarta.validation.constraints.NotNull;

@Setter
@Getter
@Schema(description = "BOM entry")
public class BomEntryDto {

    @NotNull
    @Schema(
            description = "BOM serial number",
            example = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String serialNumber;

    @NotNull
    @Schema(
            description = "BOM Version - number or `original` string",
            example = "1",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String version;

    @NotNull
    @Schema(
            description = "RFC 3339 timestamp when this CBOM was created",
            example = "2026-01-25T21:35:05Z",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private OffsetDateTime timestamp;

    @NotNull
    @Schema(
            description = "Crypto statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoStatsDto cryptoStats;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("serialNumber", serialNumber)
                .append("version", version)
                .toString();
    }
}
