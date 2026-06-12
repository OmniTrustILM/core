package com.otilm.core.model.cbom;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import jakarta.validation.constraints.NotNull;

import java.io.Serializable;

@Setter
@Getter
@Schema(description = "Response returned after uploading a BOM")
public class BomCreateResponseDto implements Serializable {

    @NotNull
    @Schema(
            description = "CycloneDX serial number (URN, RFC-4122)",
            example = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String serialNumber;

    @NotNull
    @Schema(
            description = "CycloneDX integer version number for the BOM document",
            example = "1",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private Integer version;

    @NotNull
    @Schema(
            description = "CBOM statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoStatsDto cryptoStats;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("serialNumber", serialNumber)
                .append("version", version)
                .append("cryptoStats", cryptoStats)
                .toString();
    }
}
