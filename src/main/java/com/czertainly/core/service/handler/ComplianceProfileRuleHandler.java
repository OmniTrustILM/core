package com.czertainly.core.service.handler;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.compliance.v2.ComplianceProfileUpdateRequestDto;
import com.czertainly.api.model.client.compliance.v2.ProviderComplianceRulesRequestDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.compliance.v2.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceRuleAvailabilityStatus;
import com.czertainly.api.model.core.compliance.ComplianceRuleStatus;
import com.czertainly.api.model.core.compliance.v2.*;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.FunctionGroupDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.model.compliance.ComplianceRulesGroupsBatchDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.NullUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Component
@Transactional
public class ComplianceProfileRuleHandler {

    private static final String NOT_AVAILABLE_RULE_NAME = "<Not Available>";

    private ConnectorApiFactory connectorApiFactory;

    private ConnectorRepository connectorRepository;
    private ComplianceInternalRuleRepository internalRuleRepository;
    private ComplianceProfileRepository complianceProfileRepository;
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;

    private AttributeEngine attributeEngine;

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setInternalRuleRepository(ComplianceInternalRuleRepository internalRuleRepository) {
        this.internalRuleRepository = internalRuleRepository;
    }

    @Autowired
    public void setComplianceProfileRepository(ComplianceProfileRepository complianceProfileRepository) {
        this.complianceProfileRepository = complianceProfileRepository;
    }

    @Autowired
    public void setComplianceProfileRuleRepository(ComplianceProfileRuleRepository complianceProfileRuleRepository) {
        this.complianceProfileRuleRepository = complianceProfileRuleRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    public ComplianceProfileDto mapComplianceProfileDto(UUID complianceProfileUuid) throws NotFoundException, ConnectorException {
        ComplianceProfile complianceProfile = complianceProfileRepository.findWithAssociationsByUuid(complianceProfileUuid).orElseThrow(() -> new NotFoundException(ComplianceProfile.class, complianceProfileUuid));
        ComplianceProfileDto dto = complianceProfile.mapToDto();

        Map<String, List<ComplianceProfileRule>> profileRulesMapping = new HashMap<>();
        Map<String, List<ComplianceProfileRule>> profileGroupsMapping = new HashMap<>();
        Map<String, ComplianceRulesBatchRequestDto> providerRulesRequestMapping = new HashMap<>();
        for (ComplianceProfileRule complianceProfileRule : complianceProfile.getComplianceRules()) {
            if (complianceProfileRule.getInternalRuleUuid() != null) {
                String updatedReason = null;
                ComplianceRuleAvailabilityStatus availabilityStatus = ComplianceRuleAvailabilityStatus.AVAILABLE;
                if (complianceProfileRule.getInternalRule().getResource() != complianceProfileRule.getResource()) {
                    availabilityStatus = ComplianceRuleAvailabilityStatus.UPDATED;
                    updatedReason = "Resource changed from '%s' to '%s'".formatted(complianceProfileRule.getResource().getLabel(), complianceProfileRule.getInternalRule().getResource().getLabel());
                }
                dto.getInternalRules().add(complianceProfileRule.getInternalRule().mapToComplianceRuleDto(complianceProfileRule.getResource(), availabilityStatus, updatedReason));
            } else {
                String key = "%s|%s".formatted(complianceProfileRule.getConnectorUuid(), complianceProfileRule.getKind());

                ComplianceRulesBatchRequestDto providerRulesRequest = providerRulesRequestMapping.get(key);
                if (providerRulesRequest == null) {
                    providerRulesRequest = new ComplianceRulesBatchRequestDto();
                    providerRulesRequestMapping.put(key, providerRulesRequest);

                    profileRulesMapping.put(key, new ArrayList<>());
                    profileGroupsMapping.put(key, new ArrayList<>());
                }

                if (complianceProfileRule.getComplianceRuleUuid() != null) {
                    providerRulesRequest.getRuleUuids().add(complianceProfileRule.getComplianceRuleUuid());
                    profileRulesMapping.get(key).add(complianceProfileRule);
                } else {
                    providerRulesRequest.getGroupUuids().add(complianceProfileRule.getComplianceGroupUuid());
                    profileGroupsMapping.get(key).add(complianceProfileRule);
                }
            }
        }

        for (var entry : providerRulesRequestMapping.entrySet()) {
            String[] keyParts = entry.getKey().split("\\|");
            ComplianceRulesGroupsBatchDto providerRulesBatch = getComplianceProviderRulesBatch(UUID.fromString(keyParts[0]), keyParts[1], entry.getValue().getRuleUuids(), entry.getValue().getGroupUuids(), false);

            ProviderComplianceRulesDto providerComplianceRulesDto = new ProviderComplianceRulesDto();
            providerComplianceRulesDto.setConnectorUuid(providerRulesBatch.getConnectorUuid());
            providerComplianceRulesDto.setConnectorName(providerRulesBatch.getConnectorName());
            providerComplianceRulesDto.setKind(providerRulesBatch.getKind());

            // map rules to DTO
            for (ComplianceProfileRule complianceProfileRule : profileRulesMapping.get(entry.getKey())) {
                ComplianceRuleResponseDto providerRule = providerRulesBatch.getRules().get(complianceProfileRule.getComplianceRuleUuid());
                providerComplianceRulesDto.getRules().add(mapProviderRuleDto(complianceProfileRule, providerRule));
            }

            // map groups to DTO
            for (ComplianceProfileRule complianceProfileRule : profileGroupsMapping.get(entry.getKey())) {
                ComplianceGroupBatchResponseDto providerGroup = providerRulesBatch.getGroups().get(complianceProfileRule.getComplianceGroupUuid());
                providerComplianceRulesDto.getGroups().add(mapProviderGroupDto(complianceProfileRule, providerGroup));
            }

            dto.getProviderRules().add(providerComplianceRulesDto);
        }

        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.COMPLIANCE_PROFILE, complianceProfileUuid));

        return dto;
    }

    public ComplianceCheckRuleDto mapComplianceCheckProviderRuleDto(UUID connectorUuid, String connectorName, String kind, UUID providerRuleUuid, ComplianceRuleStatus status, ComplianceRuleResponseDto providerRule) {
        ComplianceCheckRuleDto dto = new ComplianceCheckRuleDto();
        dto.setUuid(providerRuleUuid);
        dto.setConnectorUuid(connectorUuid);
        dto.setConnectorName(connectorName);
        dto.setKind(kind);
        dto.setStatus(status);

        if (providerRule != null) {
            dto.setName(providerRule.getName());
            dto.setDescription(providerRule.getDescription());
            dto.setResource(providerRule.getResource());
            if (providerRule.getAttributes() != null && !providerRule.getAttributes().isEmpty()) {
                mapFromProfileRule(connectorUuid, kind, providerRuleUuid, providerRule.getAttributes(), dto);
            }

            return dto;
        }

        mapFromProfileRule(connectorUuid, kind, providerRuleUuid, null, dto);
        dto.setName(NOT_AVAILABLE_RULE_NAME);
        if (dto.getResource() == null) {
            dto.setResource(Resource.NONE);
        }

        return dto;
    }

    private void mapFromProfileRule(UUID connectorUuid, String kind, UUID providerRuleUuid, List<BaseAttribute> attributes, ComplianceCheckRuleDto ruleDto) {
        List<ComplianceProfileRule> profileRules = complianceProfileRuleRepository.findByConnectorUuidAndKindAndComplianceRuleUuid(connectorUuid, kind, providerRuleUuid);
        if (profileRules.isEmpty()) {
            return;
        }

        ComplianceProfileRule matchedProfileRule = profileRules.getFirst();
        if (attributes != null && !attributes.isEmpty()) {
            for (ComplianceProfileRule profileRule : profileRules) {
                if (profileRule.getAttributes() != null && !profileRule.getAttributes().isEmpty()) {
                    try {
                        AttributeEngine.validateRequestDataAttributes(attributes, profileRule.getAttributes(), true);
                        matchedProfileRule = profileRule;
                        break;
                    } catch (ValidationException ignored) {
                        // continue to next rule if attributes do not match
                    }
                }
            }
        }

        ruleDto.setResource(matchedProfileRule.getResource());
        ruleDto.setAttributes(attributeEngine.getRequestDataAttributesContent(attributes, matchedProfileRule.getAttributes()));
    }

    private ComplianceRuleDto mapProviderRuleDto(ComplianceProfileRule complianceProfileRule, ComplianceRuleResponseDto providerRule) throws ValidationException {
        ComplianceRuleDto ruleDto = new ComplianceRuleDto();
        ruleDto.setUuid(complianceProfileRule.getComplianceRuleUuid());
        ruleDto.setResource(complianceProfileRule.getResource());

        var type = getComplianceRuleTypeFromName(complianceProfileRule.getResource(), complianceProfileRule.getType());
        if (type != null) {
            ruleDto.setType(type.getCode());
        }

        if (providerRule == null) {
            ruleDto.setName(NOT_AVAILABLE_RULE_NAME);
            ruleDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.NOT_AVAILABLE);
            return ruleDto;
        }

        ruleDto.setName(providerRule.getName());
        ruleDto.setDescription(providerRule.getDescription());
        ruleDto.setGroupUuid(providerRule.getGroupUuid());
        ruleDto.setFormat(providerRule.getFormat());

        // set other properties based on comparison, if not set before as newly created rule association
        StringBuilder updatedReason = new StringBuilder();
        if (complianceProfileRule.getAvailabilityStatus() == null) {
            if (ruleDto.getResource() != providerRule.getResource()) {
                updatedReason.append("Resource changed from '%s' to '%s'%n".formatted(complianceProfileRule.getResource().getLabel(), providerRule.getResource().getLabel()));
            }
            if (!Objects.equals(ruleDto.getType(), providerRule.getType())) {
                updatedReason.append("Resource type changed from '%s' to '%s'%n".formatted(Objects.toString(complianceProfileRule.getType(), "NULL"), Objects.toString(providerRule.getType(), "NULL")));
            }
            try {
                AttributeEngine.validateRequestDataAttributes(providerRule.getAttributes(), complianceProfileRule.getAttributes(), true);
            } catch (ValidationException e) {
                updatedReason.append("Rule attributes changed: %s%n".formatted(e.getMessage()));
            }
        } else {
            // for new rule association, just validate rule attributes
            AttributeEngine.validateRequestDataAttributes(providerRule.getAttributes(), complianceProfileRule.getAttributes(), true);
        }

        if (!updatedReason.isEmpty()) {
            ruleDto.setUpdatedReason(updatedReason.toString());
            ruleDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.UPDATED);
        } else {
            ruleDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.AVAILABLE);
        }
        ruleDto.setAttributes(attributeEngine.getRequestDataAttributesContent(providerRule.getAttributes(), complianceProfileRule.getAttributes()));

        return ruleDto;
    }

    private ComplianceGroupDto mapProviderGroupDto(ComplianceProfileRule complianceProfileRule, ComplianceGroupBatchResponseDto providerGroup) throws ValidationException {
        ComplianceGroupDto groupDto = new ComplianceGroupDto();
        groupDto.setUuid(complianceProfileRule.getComplianceGroupUuid());
        groupDto.setResource(complianceProfileRule.getResource());

        if (providerGroup == null) {
            groupDto.setName(NOT_AVAILABLE_RULE_NAME);
            groupDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.NOT_AVAILABLE);
            return groupDto;
        }

        groupDto.setName(providerGroup.getName());
        groupDto.setDescription(providerGroup.getDescription());

        // set other properties based on comparison, if not set before as newly created rule association
        if (complianceProfileRule.getAvailabilityStatus() == null) {
            if (complianceProfileRule.getResource() != providerGroup.getResource()) {
                groupDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.UPDATED);
                groupDto.setUpdatedReason("Resource changed from '%s' to '%s'".formatted(complianceProfileRule.getResource() == null ? "NULL" : complianceProfileRule.getResource().getLabel(), providerGroup.getResource() == null ? "NULL" : providerGroup.getResource().getLabel()));
            } else {
                groupDto.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.AVAILABLE);
            }
        }

        return groupDto;
    }

    public ComplianceProfileDto updateComplianceProfileRules(ComplianceProfile complianceProfile, ComplianceProfileUpdateRequestDto request) throws ConnectorException, NotFoundException {
        ComplianceProfileDto complianceProfileDto = complianceProfile.mapToDto();

        // delete all compliance rules associations
        complianceProfileRuleRepository.deleteByComplianceProfileUuid(complianceProfile.getUuid());

        // handle internal rules
        for (UUID internalRuleUuid : request.getInternalRules()) {
            ComplianceProfileRule profileRule = createComplianceProfileInternalRuleAssoc(complianceProfile.getUuid(), internalRuleUuid);
            complianceProfileDto.getInternalRules().add(profileRule.getInternalRule().mapToComplianceRuleDto(profileRule.getResource(), profileRule.getAvailabilityStatus(), null));
        }

        // handle providers rules
        for (ProviderComplianceRulesRequestDto providerRulesDto : request.getProviderRules()) {
            Set<UUID> ruleUuids = providerRulesDto.getRules().stream().map(ComplianceRuleRequestDto::getUuid).collect(Collectors.toSet());
            ComplianceRulesGroupsBatchDto providerBatchDto = getComplianceProviderRulesBatch(providerRulesDto.getConnectorUuid(), providerRulesDto.getKind(), ruleUuids, providerRulesDto.getGroups(), false);

            ProviderComplianceRulesDto providerComplianceRulesDto = new ProviderComplianceRulesDto();
            providerComplianceRulesDto.setConnectorUuid(providerBatchDto.getConnectorUuid());
            providerComplianceRulesDto.setConnectorName(providerBatchDto.getConnectorName());
            providerComplianceRulesDto.setKind(providerBatchDto.getKind());
            for (ComplianceRuleRequestDto providerRuleRequest : providerRulesDto.getRules()) {
                ComplianceRuleResponseDto providerRule = providerBatchDto.getRules().get(providerRuleRequest.getUuid());
                if (providerRule == null) {
                    throw new NotFoundException("Compliance rule with UUID %s not found in provider %s".formatted(providerRuleRequest.getUuid(), providerBatchDto.getConnectorName()));
                }

                // associate provider rule with compliance profile
                ComplianceProfileRule complianceProfileRule = createComplianceProfileProviderRuleAssoc(complianceProfile.getUuid(), providerRulesDto.getConnectorUuid(), providerRulesDto.getKind(), providerRule, providerRuleRequest.getAttributes());
                ComplianceRuleDto ruleDto = mapProviderRuleDto(complianceProfileRule, providerRule);
                providerComplianceRulesDto.getRules().add(ruleDto);
            }

            for (UUID providerGroupUuid : providerRulesDto.getGroups()) {
                ComplianceGroupBatchResponseDto providerGroup = providerBatchDto.getGroups().get(providerGroupUuid);
                if (providerGroup == null) {
                    throw new NotFoundException("Compliance group with UUID %s not found in provider %s".formatted(providerGroupUuid, providerBatchDto.getConnectorName()));
                }

                // associate provider group with compliance profile
                ComplianceProfileRule complianceProfileRule = createComplianceProfileProviderGroupAssoc(complianceProfile.getUuid(), providerRulesDto.getConnectorUuid(), providerRulesDto.getKind(), providerGroup);
                ComplianceGroupDto groupDto = mapProviderGroupDto(complianceProfileRule, providerGroup);
                providerComplianceRulesDto.getGroups().add(groupDto);
            }
            complianceProfileDto.getProviderRules().add(providerComplianceRulesDto);
        }

        return complianceProfileDto;
    }

    public ComplianceProfileRule createComplianceProfileInternalRuleAssoc(UUID complianceProfileUuid, UUID internalRuleUuid) throws NotFoundException {
        ComplianceInternalRule internalRule = internalRuleRepository.findByUuid(SecuredUUID.fromUUID(internalRuleUuid)).orElseThrow(() -> new NotFoundException(ComplianceInternalRule.class, internalRuleUuid));
        if (!internalRule.getResource().complianceSubject()) {
            throw new ValidationException("Internal rule '%s' with resource %s cannot be associated with compliance profile because resource does not support compliance check".formatted(internalRule.getName(), internalRule.getResource().getLabel()));
        }

        ComplianceProfileRule complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfileUuid(complianceProfileUuid);
        complianceProfileRule.setInternalRuleUuid(internalRuleUuid);
        complianceProfileRule.setInternalRule(internalRule);
        complianceProfileRule.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.AVAILABLE);
        complianceProfileRule.setResource(internalRule.getResource());
        complianceProfileRuleRepository.save(complianceProfileRule);

        return complianceProfileRule;
    }

    public ComplianceProfileRule createComplianceProfileProviderRuleAssoc(UUID complianceProfileUuid, UUID connectorUuid, String kind, ComplianceRuleResponseDto providerRule, List<RequestAttribute> requestAttributes) {
        if (!providerRule.getResource().complianceSubject()) {
            throw new ValidationException("Provider rule '%s' with resource %s cannot be associated with compliance profile because resource does not support compliance check".formatted(providerRule.getName(), providerRule.getResource().getLabel()));
        }

        ComplianceProfileRule complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfileUuid(complianceProfileUuid);
        complianceProfileRule.setComplianceRuleUuid(providerRule.getUuid());
        complianceProfileRule.setConnectorUuid(connectorUuid);
        complianceProfileRule.setKind(kind);
        complianceProfileRule.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.AVAILABLE);
        complianceProfileRule.setResource(providerRule.getResource());
        complianceProfileRule.setAttributes(requestAttributes);

        var type = getComplianceRuleTypeFromCode(providerRule.getResource(), providerRule.getType());
        if (type != null) {
            complianceProfileRule.setType(type.name());
        }
        complianceProfileRuleRepository.save(complianceProfileRule);

        return complianceProfileRule;
    }

    public ComplianceProfileRule createComplianceProfileProviderGroupAssoc(UUID complianceProfileUuid, UUID connectorUuid, String kind, ComplianceGroupResponseDto providerGroup) {
        if (providerGroup.getResource() != null && !providerGroup.getResource().complianceSubject()) {
            throw new ValidationException("Provider group '%s' with resource %s cannot be associated with compliance profile because resource does not support compliance check".formatted(providerGroup.getName(), providerGroup.getResource().getLabel()));
        }

        ComplianceProfileRule complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfileUuid(complianceProfileUuid);
        complianceProfileRule.setComplianceGroupUuid(providerGroup.getUuid());
        complianceProfileRule.setConnectorUuid(connectorUuid);
        complianceProfileRule.setKind(kind);
        complianceProfileRule.setAvailabilityStatus(ComplianceRuleAvailabilityStatus.AVAILABLE);
        complianceProfileRule.setResource(providerGroup.getResource());
        complianceProfileRuleRepository.save(complianceProfileRule);

        return complianceProfileRule;
    }

    public ComplianceRulesGroupsBatchDto getComplianceProviderRulesBatch(UUID connectorUuid, String kind, Set<UUID> ruleUuids, Set<UUID> groupUuids, boolean withGroupRules) throws NotFoundException, ConnectorException {
        Connector connector = connectorRepository.findByUuid(connectorUuid).orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        ConnectorDto connectorDto = connector.mapToDto();
        FunctionGroupCode functionGroup = validateComplianceProvider(connectorDto, kind);

        ComplianceRulesGroupsBatchDto rulesBatchDto = new ComplianceRulesGroupsBatchDto();
        rulesBatchDto.setConnectorUuid(connectorUuid);
        rulesBatchDto.setConnectorName(connectorDto.getName());
        rulesBatchDto.setKind(kind);
        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER_V2) {
            ComplianceRulesBatchRequestDto rulesBatchRequestDto = new ComplianceRulesBatchRequestDto();
            rulesBatchRequestDto.setGroupUuids(groupUuids);
            rulesBatchRequestDto.setRuleUuids(ruleUuids);
            rulesBatchRequestDto.setWithGroupRules(withGroupRules);
            ComplianceRulesBatchResponseDto batchResponseDto = connectorApiFactory.getComplianceApiClientV2(connectorDto).getComplianceRulesBatch(connectorDto, kind, rulesBatchRequestDto);

            rulesBatchDto.setRules(batchResponseDto.getRules().stream().collect(Collectors.toMap(ComplianceRuleResponseDto::getUuid, r -> r)));
            rulesBatchDto.setGroups(batchResponseDto.getGroups().stream().collect(Collectors.toMap(ComplianceGroupBatchResponseDto::getUuid, g -> g)));
        } else {
            getComplianceProviderV1RulesBatch(rulesBatchDto, connectorDto, kind, ruleUuids, groupUuids, withGroupRules);
        }

        return rulesBatchDto;
    }

    public ComplianceRuleResponseDto getProviderRule(UUID connectorUuid, String kind, UUID ruleUuid) throws NotFoundException, ConnectorException {
        Connector connector = connectorRepository.findByUuid(connectorUuid).orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        ConnectorDto connectorDto = connector.mapToDto();
        FunctionGroupCode functionGroup = validateComplianceProvider(connectorDto, kind);

        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER_V2) {
            return connectorApiFactory.getComplianceApiClientV2(connectorDto).getComplianceRule(connectorDto, kind, ruleUuid);
        } else {
            String ruleUuidStr = ruleUuid.toString();
            ComplianceRuleResponseDto resultRule = null;
            var providerRules = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceRules(connectorDto, kind, null);
            for (var providerRule : providerRules) {
                if (providerRule.getUuid().equals(ruleUuidStr)) {
                    resultRule = new ComplianceRuleResponseDto();
                    resultRule.setUuid(ruleUuid);
                    resultRule.setGroupUuid(NullUtil.parseUuidOrNull(providerRule.getGroupUuid()));
                    resultRule.setName(providerRule.getName());
                    resultRule.setDescription(providerRule.getDescription());
                    resultRule.setResource(Resource.CERTIFICATE);
                    resultRule.setType(providerRule.getCertificateType() != null ? providerRule.getCertificateType().getCode() : null);
                    resultRule.setAttributes(providerRule.getAttributes());
                    break;
                }
            }
            if (resultRule == null) {
                throw new NotFoundException("Compliance rule with UUID %s not found in provider %s".formatted(ruleUuid, connectorDto.getName()));
            }
            return resultRule;
        }
    }

    public ComplianceGroupResponseDto getProviderGroup(UUID connectorUuid, String kind, UUID groupUuid) throws NotFoundException, ConnectorException {
        Connector connector = connectorRepository.findByUuid(connectorUuid).orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        ConnectorDto connectorDto = connector.mapToDto();
        FunctionGroupCode functionGroup = validateComplianceProvider(connectorDto, kind);

        if (functionGroup == FunctionGroupCode.COMPLIANCE_PROVIDER_V2) {
            return connectorApiFactory.getComplianceApiClientV2(connectorDto).getComplianceGroup(connectorDto, kind, groupUuid);
        } else {
            String groupUuidStr = groupUuid.toString();
            ComplianceGroupResponseDto resultGroup = null;
            var providerGroups = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceGroups(connectorDto, kind);
            for (var providerGroup : providerGroups) {
                if (providerGroup.getUuid().equals(groupUuidStr)) {
                    resultGroup = new ComplianceGroupResponseDto();
                    resultGroup.setUuid(groupUuid);
                    resultGroup.setName(providerGroup.getName());
                    resultGroup.setDescription(providerGroup.getDescription());
                    resultGroup.setResource(Resource.CERTIFICATE);
                    break;
                }
            }
            if (resultGroup == null) {
                throw new NotFoundException("Compliance group with UUID %s not found in provider %s".formatted(groupUuid, connectorDto.getName()));
            }
            return resultGroup;
        }
    }

    public void getComplianceProviderV1RulesBatch(ComplianceRulesGroupsBatchDto batchDto, ConnectorDto connectorDto, String kind, Set<UUID> ruleUuids, Set<UUID> groupUuids, boolean withGroupRules) throws ConnectorException {
        if (ruleUuids == null) ruleUuids = new HashSet<>();
        if (groupUuids == null) groupUuids = new HashSet<>();

        if (!groupUuids.isEmpty()) {
            Set<UUID> finalGroupUuids = groupUuids;
            batchDto.setGroups(connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceGroups(connectorDto, kind).stream().filter(g -> finalGroupUuids.contains(UUID.fromString(g.getUuid()))).collect(Collectors.toMap(g -> UUID.fromString(g.getUuid()), g -> {
                var providerGroupBatchDto = new ComplianceGroupBatchResponseDto();
                providerGroupBatchDto.setUuid(UUID.fromString(g.getUuid()));
                providerGroupBatchDto.setName(g.getName());
                providerGroupBatchDto.setDescription(g.getDescription());
                providerGroupBatchDto.setResource(Resource.CERTIFICATE);
                return providerGroupBatchDto;
            })));
        }

        if (ruleUuids.isEmpty() && (!withGroupRules || groupUuids.isEmpty())) {
            return;
        }

        var providerRules = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceRules(connectorDto, kind, null);
        for (var providerRule : providerRules) {
            UUID providerRuleUuid = UUID.fromString(providerRule.getUuid());
            UUID providerRuleGroupUuid = NullUtil.parseUuidOrNull(providerRule.getGroupUuid());
            if (!ruleUuids.contains(providerRuleUuid) && (!withGroupRules || providerRuleGroupUuid == null || !groupUuids.contains(providerRuleGroupUuid))) {
                continue;
            }

            ComplianceRuleResponseDto ruleResponseDto = new ComplianceRuleResponseDto();
            ruleResponseDto.setUuid(providerRuleUuid);
            ruleResponseDto.setGroupUuid(providerRuleGroupUuid);
            ruleResponseDto.setName(providerRule.getName());
            ruleResponseDto.setDescription(providerRule.getDescription());
            ruleResponseDto.setResource(Resource.CERTIFICATE);
            ruleResponseDto.setType(providerRule.getCertificateType() != null ? providerRule.getCertificateType().getCode() : null);
            ruleResponseDto.setAttributes(providerRule.getAttributes());

            if (withGroupRules && providerRuleGroupUuid != null) {
                ComplianceGroupBatchResponseDto providerGroupBatchDto = batchDto.getGroups().get(providerRuleGroupUuid);
                if (providerGroupBatchDto != null) {
                    providerGroupBatchDto.getRules().add(ruleResponseDto);
                }
            }
            batchDto.getRules().put(providerRuleUuid, ruleResponseDto);
        }
    }

    public static FunctionGroupCode validateComplianceProvider(ConnectorDto connectorDto, String kind) throws ValidationException {
        FunctionGroupDto functionGroup = connectorDto.getFunctionGroups().stream().filter(fg -> fg.getFunctionGroupCode().equals(FunctionGroupCode.COMPLIANCE_PROVIDER_V2) && fg.getKinds().contains(kind)).findFirst().orElse(null);
        if (functionGroup == null) {
            functionGroup = connectorDto.getFunctionGroups().stream().filter(fg -> fg.getFunctionGroupCode().equals(FunctionGroupCode.COMPLIANCE_PROVIDER) && fg.getKinds().contains(kind)).findFirst().orElse(null);
        }
        if (functionGroup == null) {
            throw new ValidationException("Connector '%s' does not implement compliance provider function group with kind '%s'".formatted(connectorDto.getName(), kind));
        }

        return functionGroup.getFunctionGroupCode();
    }

    public static <E extends Enum<E> & IPlatformEnum> E getComplianceRuleTypeFromName(Resource resource, String typeName) {
        if (typeName == null) {
            return null;
        }
        try {
            return (E) switch (resource) {
                case CERTIFICATE, CERTIFICATE_REQUEST -> CertificateType.valueOf(typeName);
                case CRYPTOGRAPHIC_KEY, CRYPTOGRAPHIC_KEY_ITEM -> KeyType.valueOf(typeName);
                default ->
                        throw new ValidationException("Compliance rule with resource '%s' cannot be associated with compliance profile because resource does not support compliance check".formatted(resource.getLabel()));
            };
        } catch (Exception e) {
            throw new ValidationException("Compliance rule with resource '%s' has not supported type '%s'".formatted(resource.getLabel(), typeName));
        }
    }

    public static <E extends Enum<E> & IPlatformEnum> E getComplianceRuleTypeFromCode(Resource resource, String typeCode) {
        if (typeCode == null) {
            return null;
        }
        try {
            return (E) switch (resource) {
                case CERTIFICATE, CERTIFICATE_REQUEST -> CertificateType.fromCode(typeCode);
                case CRYPTOGRAPHIC_KEY, CRYPTOGRAPHIC_KEY_ITEM -> KeyType.findByCode(typeCode);
                default ->
                        throw new ValidationException("Compliance rule with resource '%s' cannot be associated with compliance profile because resource does not support compliance check".formatted(resource.getLabel()));
            };
        } catch (Exception e) {
            throw new ValidationException("Type '%s' is not supported for resource '%s'".formatted(typeCode, resource.getLabel()));
        }
    }
}
