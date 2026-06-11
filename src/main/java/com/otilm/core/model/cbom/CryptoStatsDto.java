package com.otilm.core.model.cbom;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.io.Serializable;

@Setter
@Getter
public class CryptoStatsDto implements Serializable {

    @NotNull
    @Valid
    @Schema(
            description = "Cryptographic assets statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoAssetsDto cryptoAssets;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("cryptoAssets", cryptoAssets)
                .toString();
    }
}
