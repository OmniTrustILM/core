package com.otilm.core.model.compliance;

import com.otilm.api.model.connector.compliance.v2.ComplianceGroupBatchResponseDto;
import com.otilm.api.model.connector.compliance.v2.ComplianceRuleResponseDto;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ComplianceRulesGroupsBatchDto {

    private UUID connectorUuid;
    private String connectorName;
    private String kind;
    private Map<UUID, ComplianceRuleResponseDto> rules = new HashMap<>();
    private Map<UUID, ComplianceGroupBatchResponseDto> groups = new HashMap<>();

}
