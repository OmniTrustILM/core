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
public class CryptoAssetsDto implements Serializable {

    @Schema(
            description = "Total number of cryptographic assets",
            example = "1",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private Integer total;

    @NotNull
    @Valid
    @Schema(
            description = "Algorithms statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoAssetCountDto algorithms;

    @NotNull
    @Valid
    @Schema(
            description = "Certificates statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoAssetCountDto certificates;

    @NotNull
    @Valid
    @Schema(
            description = "Protocols statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoAssetCountDto protocols;

    @NotNull
    @Valid
    @Schema(
            description = "Related crypto materials statistics",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private CryptoAssetCountDto relatedCryptoMaterials;

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
        .append("total", total)
        .append("algorithms", algorithms)
        .append("certificates", certificates)
        .append("protocols", protocols)
        .append("relatedCryptoMaterials", relatedCryptoMaterials)
        .toString();
    }
}
