package com.otilm.core.model.compliance;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@ToString
public class ComplianceResultRulesDto implements Serializable {

    @Schema(description = "Not Compliant Rules", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Set<UUID> notCompliant = new HashSet<>();

    @Schema(description = "Not Applicable Rules", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Set<UUID> notApplicable = new HashSet<>();

    @Schema(description = "Not Available Rules", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Set<UUID> notAvailable = new HashSet<>();

}
