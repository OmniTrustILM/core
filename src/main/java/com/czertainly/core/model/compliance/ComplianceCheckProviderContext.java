package com.czertainly.core.model.compliance;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.client.v2.ComplianceSyncApiClient;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.connector.compliance.ComplianceRequestRulesDto;
import com.czertainly.api.model.connector.compliance.v2.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.ComplianceRuleAvailabilityStatus;
import com.czertainly.api.model.core.compliance.ComplianceRuleStatus;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.ComplianceProfileRule;
import com.czertainly.core.dao.entity.ComplianceSubject;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.service.handler.ComplianceProfileRuleHandler;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
public class ComplianceCheckProviderContext {
    private final UUID connectorUuid;
    private final ConnectorDto connectorDto;
    private final String kind;
    private final FunctionGroupCode functionGroup;

    private final ComplianceProfileRuleHandler ruleHandler;
    private final ConnectorApiFactory connectorApiFactory;

    private final ComplianceRulesBatchRequestDto rulesBatchRequestDto = new ComplianceRulesBatchRequestDto();
    private ComplianceRulesGroupsBatchDto rulesGroupsBatchDto;
    private ConnectorException failedStatusException;

    private ComplianceRequestDto complianceRequestDto;
    private com.czertainly.api.model.connector.compliance.ComplianceRequestDto complianceRequestDtoV1;

    public ComplianceCheckProviderContext(Connector connector, String kind, ComplianceProfileRuleHandler ruleHandler, ConnectorApiFactory connectorApiFactory) {
        this.connectorUuid = connector.getUuid();
        this.connectorDto = connector.mapToDto();
        this.kind = kind;
        this.ruleHandler = ruleHandler;
        this.connectorApiFactory = connectorApiFactory;
        this.functionGroup = ComplianceProfileRuleHandler.validateComplianceProvider(connectorDto, kind);
        this.rulesBatchRequestDto.setWithGroupRules(functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER);
    }

    /**
     * Prepares the compliance check request for the given subject and resource/type.
     *
     * @param subject  Compliance subject for which the check is being prepared
     * @param resource Resource of the compliance subject (null if not applicable)
     * @param type     Type of the compliance subject (null if not applicable)
     * @throws ConnectorException If there is an error communicating with the connector
     */
    public void prepareComplianceCheckRequestForSubject(ComplianceSubject subject, Resource resource, IPlatformEnum type) throws ConnectorException {
        if (rulesGroupsBatchDto == null) {
            if (failedStatusException != null) {
                throw failedStatusException;
            }
            try {
                rulesGroupsBatchDto = ruleHandler.getComplianceProviderRulesBatch(connectorUuid, kind, rulesBatchRequestDto.getRuleUuids(), rulesBatchRequestDto.getGroupUuids(), rulesBatchRequestDto.isWithGroupRules());
            } catch (Exception e) {
                failedStatusException = new ConnectorException(e.getMessage(), e);
                throw failedStatusException;
            }
        }

        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER) {
            complianceRequestDtoV1 = new com.czertainly.api.model.connector.compliance.ComplianceRequestDto();
            complianceRequestDtoV1.setCertificate(subject.getContentData());
            complianceRequestDtoV1.setRules(new ArrayList<>());
        } else {
            complianceRequestDto = new ComplianceRequestDto();
            complianceRequestDto.setResource(resource);
            complianceRequestDto.setType(type != null ? type.getCode() : null);
            complianceRequestDto.setData(subject.getContentData());
            complianceRequestDto.setRules(new ArrayList<>());
        }
    }


    /**
     * Adds a provider compliance profile rule to the compliance check request.
     *
     * @param profileRule Compliance profile rule to be added to check request
     * @return null if the rule/group was added successfully
     * ComplianceRuleStatus.NA if the rule is not applicable (e.g. resource/type do not match)
     * ComplianceRuleStatus.NOT_AVAILABLE if the rule/group is not available in the provider
     */
    public ComplianceRuleStatus addProviderRuleToCheck(ComplianceProfileRule profileRule) {
        if (profileRule.getComplianceRuleUuid() != null) {
            ComplianceRuleResponseDto providerRule = rulesGroupsBatchDto.getRules().get(profileRule.getComplianceRuleUuid());
            ComplianceRuleAvailabilityStatus availabilityStatus = getRuleAvailabilityStatus(profileRule, providerRule);
            if (availabilityStatus != ComplianceRuleAvailabilityStatus.AVAILABLE) {
                return availabilityStatus == ComplianceRuleAvailabilityStatus.NOT_AVAILABLE ? ComplianceRuleStatus.NOT_AVAILABLE : ComplianceRuleStatus.NA;
            }

            if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER) {
                ComplianceRequestRulesDto providerRuleRequest = new ComplianceRequestRulesDto();
                providerRuleRequest.setUuid(providerRule.getUuid().toString());
                providerRuleRequest.setAttributes(profileRule.getAttributes());
                complianceRequestDtoV1.getRules().add(providerRuleRequest);
            } else {
                ComplianceRuleRequestDto providerRuleRequest = new ComplianceRuleRequestDto();
                providerRuleRequest.setUuid(providerRule.getUuid());
                providerRuleRequest.setAttributes(profileRule.getAttributes());
                complianceRequestDto.getRules().add(providerRuleRequest);
            }
            return null;
        }

        ComplianceGroupBatchResponseDto providerGroup = rulesGroupsBatchDto.getGroups().get(profileRule.getComplianceGroupUuid());
        ComplianceRuleAvailabilityStatus availabilityStatus = getGroupAvailabilityStatus(profileRule, providerGroup);
        if (availabilityStatus != ComplianceRuleAvailabilityStatus.AVAILABLE) {
            return availabilityStatus == ComplianceRuleAvailabilityStatus.NOT_AVAILABLE ? ComplianceRuleStatus.NOT_AVAILABLE : ComplianceRuleStatus.NA;
        }

        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER) {
            for (ComplianceRuleResponseDto providerRule : providerGroup.getRules()) {
                ComplianceRequestRulesDto providerRuleRequest = new ComplianceRequestRulesDto();
                providerRuleRequest.setUuid(providerRule.getUuid().toString());
                complianceRequestDtoV1.getRules().add(providerRuleRequest);
            }
        } else {
            ComplianceRuleRequestDto providerGroupRequest = new ComplianceRuleRequestDto();
            providerGroupRequest.setUuid(providerGroup.getUuid());
            complianceRequestDto.getGroups().add(providerGroup.getUuid());
        }
        return null;
    }

    /**
     * Executes the compliance check request against the compliance provider according to the function group.
     *
     * @return ComplianceResponseDto containing the results of the compliance check
     * @throws ConnectorException If there is an error communicating with the connector
     */
    public ComplianceResponseDto executeComplianceCheck() throws ConnectorException {
        ComplianceResponseDto complianceResponse = new ComplianceResponseDto();
        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER) {
            if (!complianceRequestDtoV1.getRules().isEmpty()) {
                com.czertainly.api.interfaces.client.v1.ComplianceSyncApiClient complianceApiClientV1 = connectorApiFactory.getComplianceApiClient(connectorDto);
                var complianceResponseV1 = complianceApiClientV1.checkCompliance(connectorDto, kind, complianceRequestDtoV1);
                complianceResponse.setStatus(complianceResponseV1.getStatus());
                complianceResponse.setRules(complianceResponseV1.getRules().stream().map(r -> {
                    ComplianceResponseRuleDto ruleDto = new ComplianceResponseRuleDto();
                    ruleDto.setUuid(UUID.fromString(r.getUuid()));
                    ruleDto.setName(r.getName());
                    ruleDto.setStatus(r.getStatus());
                    return ruleDto;
                }).toList());
            }
        } else {
            if (!complianceRequestDto.getRules().isEmpty() || !complianceRequestDto.getGroups().isEmpty()) {
                ComplianceSyncApiClient complianceApiClientV2 = connectorApiFactory.getComplianceApiClientV2(connectorDto);
                complianceResponse = complianceApiClientV2.checkCompliance(connectorDto, kind, complianceRequestDto);
            }
        }
        return complianceResponse;
    }

    private ComplianceRuleAvailabilityStatus getRuleAvailabilityStatus(ComplianceProfileRule profileRule, ComplianceRuleResponseDto providerRule) {
        if (providerRule == null) {
            return ComplianceRuleAvailabilityStatus.NOT_AVAILABLE;
        }

        if (profileRule.getResource() != providerRule.getResource()) {
            return ComplianceRuleAvailabilityStatus.UPDATED;
        }

        IPlatformEnum typeEnum = null;
        try {
            typeEnum = ComplianceProfileRuleHandler.getComplianceRuleTypeFromName(profileRule.getResource(), profileRule.getType());
        } catch (ValidationException e) {
            // Ignored, handled by default value
        }
        if (typeEnum != null && !Objects.equals(typeEnum.getCode(), providerRule.getType())) {
            return ComplianceRuleAvailabilityStatus.UPDATED;
        }

        try {
            AttributeEngine.validateRequestDataAttributes(providerRule.getAttributes(), profileRule.getAttributes(), true);
        } catch (ValidationException e) {
            return ComplianceRuleAvailabilityStatus.UPDATED;
        }
        return ComplianceRuleAvailabilityStatus.AVAILABLE;
    }

    private ComplianceRuleAvailabilityStatus getGroupAvailabilityStatus(ComplianceProfileRule profileRule, ComplianceGroupBatchResponseDto providerGroup) {
        if (providerGroup == null) {
            return ComplianceRuleAvailabilityStatus.NOT_AVAILABLE;
        }

        if (profileRule.getResource() != providerGroup.getResource()) {
            return ComplianceRuleAvailabilityStatus.UPDATED;
        }
        return ComplianceRuleAvailabilityStatus.AVAILABLE;
    }
}
