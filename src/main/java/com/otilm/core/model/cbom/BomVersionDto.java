package com.otilm.core.model.cbom;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class BomVersionDto {

    @NotNull
    @Schema(
            description = "CycloneDX version number for the CBOM document",
            example = "1",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String version;

    @NotNull
    @Schema(
            description = "Timestamp",
            example = "2026-01-19T21:35:05Z",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private String timestamp;

    @NotNull
    @Schema(
            description = "CBOM statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoStatsDto cryptoStats;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
        .append("version", version)
        .append("timestamp", timestamp)
        .append("cryptoStats", cryptoStats)
        .toString();
    }
}


