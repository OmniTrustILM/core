package com.otilm.core.model.cbom;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import jakarta.validation.constraints.NotNull;

@Setter
@Getter
@Schema(description = "Statistical information about the BOM")
public class BomStatsDto {

    @NotNull
    @Schema(
            description = "Crypto statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoStatsDto cryptoStats;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("cryptoStats", cryptoStats)
                .toString();
    }
}

