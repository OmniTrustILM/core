package com.otilm.core.model.compliance;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString(callSuper = true)
public class ComplianceResultProviderRulesDto extends ComplianceResultRulesDto {

    @NotNull
    @Schema(description = "UUID of the Compliance Provider", requiredMode = Schema.RequiredMode.REQUIRED)
    private UUID connectorUuid;

    @NotNull
    @Schema(description = "Kind of the Compliance Provider", requiredMode = Schema.RequiredMode.REQUIRED)
    private String kind;

}
