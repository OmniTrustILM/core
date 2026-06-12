package com.otilm.core.model.compliance;

import com.otilm.api.model.connector.compliance.v2.ComplianceGroupBatchResponseDto;
import com.otilm.api.model.connector.compliance.v2.ComplianceRuleResponseDto;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.*;

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
