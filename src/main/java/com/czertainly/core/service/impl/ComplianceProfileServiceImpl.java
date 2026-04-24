package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.compliance.*;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.connector.compliance.ComplianceGroupsResponseDto;
import com.czertainly.api.model.connector.compliance.ComplianceRulesResponseDto;
import com.czertainly.api.model.connector.compliance.v2.ComplianceRuleRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.*;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.FunctionGroupDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service("complianceProfileServiceV1")
@Transactional
public class ComplianceProfileServiceImpl implements ComplianceProfileService {

    private com.czertainly.core.service.v2.ComplianceProfileService complianceProfileServiceV2;

    private ConnectorRepository connectorRepository;
    private RaProfileRepository raProfileRepository;
    private ComplianceProfileRepository complianceProfileRepository;
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;
    private ComplianceProfileAssociationRepository complianceProfileAssociationRepository;

    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setComplianceProfileServiceV2(com.czertainly.core.service.v2.ComplianceProfileService complianceProfileServiceV2) {
        this.complianceProfileServiceV2 = complianceProfileServiceV2;
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
    public void setComplianceProfileAssociationRepository(ComplianceProfileAssociationRepository complianceProfileAssociationRepository) {
        this.complianceProfileAssociationRepository = complianceProfileAssociationRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Override
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.LIST)
    public List<ComplianceProfilesListDto> listComplianceProfiles(SecurityFilter filter) {
        return complianceProfileRepository.findUsingSecurityFilter(filter).stream().map(ComplianceProfile::mapToListDtoV1).toList();
    }

    @Override
    public ComplianceProfileDto getComplianceProfile(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        var dtoV2 = complianceProfileServiceV2.getComplianceProfile(uuid);

        return translateComplianceProfileDtoV2(dtoV2, true);
    }

    @Override
    public ComplianceProfileDto createComplianceProfile(ComplianceProfileRequestDto request) throws AlreadyExistException, NotFoundException, ValidationException, AttributeException, ConnectorException {
        var requestV2 = new com.czertainly.api.model.client.compliance.v2.ComplianceProfileRequestDto();
        requestV2.setName(request.getName());
        requestV2.setDescription(request.getDescription());
        requestV2.setCustomAttributes(request.getCustomAttributes());
        if (request.getRules() != null) {
            for (ComplianceProfileRulesRequestDto providerRequest : request.getRules()) {
                // validate connectors
                UUID connectorUuid = UUID.fromString(providerRequest.getConnectorUuid());
                getValidatedComplianceProvider(connectorUuid, providerRequest.getKind());

                var providerRequestV2 = new com.czertainly.api.model.client.compliance.v2.ProviderComplianceRulesRequestDto();
                providerRequestV2.setConnectorUuid(connectorUuid);
                providerRequestV2.setKind(providerRequest.getKind());
                for (var providerRule : providerRequest.getRules()) {
                    providerRequestV2.getRules().add(new ComplianceRuleRequestDto(UUID.fromString(providerRule.getUuid()), providerRule.getAttributes()));
                }
                for (var providerGroupUuid : providerRequest.getGroups()) {
                    providerRequestV2.getGroups().add(UUID.fromString(providerGroupUuid));
                }
                requestV2.getProviderRules().add(providerRequestV2);
            }
        }

        var dtoV2 = complianceProfileServiceV2.createComplianceProfile(requestV2);
        return translateComplianceProfileDtoV2(dtoV2, false);
    }

    private ComplianceProfileDto translateComplianceProfileDtoV2(com.czertainly.api.model.core.compliance.v2.ComplianceProfileDto dtoV2, boolean withConnectorValidation) {
        ComplianceProfileDto dto = new ComplianceProfileDto();
        dto.setUuid(dtoV2.getUuid().toString());
        dto.setName(dtoV2.getName());
        dto.setDescription(dtoV2.getDescription());
        dto.setRules(new ArrayList<>());
        dto.setGroups(new ArrayList<>());
        dto.setCustomAttributes(dtoV2.getCustomAttributes());
        dto.setRaProfiles(getAssociatedRAProfiles(SecuredUUID.fromUUID(dtoV2.getUuid())));

        // filter out providers and non certificate rules
        for (var providerRulesV2 : dtoV2.getProviderRules()) {
            if (withConnectorValidation) {
                try {
                    getValidatedComplianceProvider(providerRulesV2.getConnectorUuid(), providerRulesV2.getKind());
                } catch (NotFoundException | ValidationException e) {
                    continue;
                }
            }

            ComplianceConnectorAndRulesDto providerRules = new ComplianceConnectorAndRulesDto();
            providerRules.setConnectorUuid(providerRulesV2.getConnectorUuid().toString());
            providerRules.setConnectorName(providerRulesV2.getConnectorName());
            providerRules.setKind(providerRulesV2.getKind());
            providerRules.setRules(new ArrayList<>());
            for (var providerRuleV2 : providerRulesV2.getRules()) {
                if (providerRuleV2.getResource() != Resource.CERTIFICATE) {
                    continue;
                }
                ComplianceRulesDto providerRule = new ComplianceRulesDto();
                providerRule.setUuid(providerRuleV2.getUuid().toString());
                providerRule.setName(providerRuleV2.getName());
                providerRule.setDescription(providerRuleV2.getDescription());
                providerRule.setCertificateType(providerRuleV2.getType() != null ? CertificateType.fromCode(providerRuleV2.getType()) : null);
                providerRule.setAttributes(providerRuleV2.getAttributes());
                providerRules.getRules().add(providerRule);
            }
            dto.getRules().add(providerRules);

            ComplianceConnectorAndGroupsDto providerGroups = new ComplianceConnectorAndGroupsDto();
            providerGroups.setConnectorUuid(providerRulesV2.getConnectorUuid().toString());
            providerGroups.setConnectorName(providerRulesV2.getConnectorName());
            providerGroups.setKind(providerRulesV2.getKind());
            providerGroups.setGroups(new ArrayList<>());
            for (var providerGroupV2 : providerRulesV2.getGroups()) {
                if (providerGroupV2.getResource() != null && providerGroupV2.getResource() != Resource.CERTIFICATE) {
                    continue;
                }
                ComplianceGroupsDto providerGroup = new ComplianceGroupsDto();
                providerGroup.setUuid(providerGroupV2.getUuid().toString());
                providerGroup.setName(providerGroupV2.getName());
                providerGroup.setDescription(providerGroupV2.getDescription());
                providerGroups.getGroups().add(providerGroup);
            }
            dto.getGroups().add(providerGroups);
        }

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.UPDATE)
    public ComplianceProfileRuleDto addRule(SecuredUUID uuid, ComplianceRuleAdditionRequestDto request) throws NotFoundException, ValidationException, ConnectorException {
        ComplianceProfile complianceProfile = complianceProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(ComplianceProfile.class, uuid));

        UUID connectorUuid = UUID.fromString(request.getConnectorUuid());
        getValidatedComplianceProvider(connectorUuid, request.getKind());
        complianceProfileRuleRepository.deleteByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(uuid.getValue(), connectorUuid, request.getKind(), UUID.fromString(request.getRuleUuid()));

        ComplianceProfileRuleDto providerRule = getProviderRule(complianceProfile.getUuid(), complianceProfile.getName(), UUID.fromString(request.getConnectorUuid()), request.getKind(), request.getRuleUuid(), request.getAttributes());

        ComplianceProfileRule complianceProfileRule = new ComplianceProfileRule();
        complianceProfileRule.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileRule.setComplianceRuleUuid(UUID.fromString(request.getRuleUuid()));
        complianceProfileRule.setConnectorUuid(connectorUuid);
        complianceProfileRule.setKind(request.getKind());
        complianceProfileRule.setResource(Resource.CERTIFICATE);
        complianceProfileRule.setType(providerRule.getCertificateType().name());
        complianceProfileRule.setAttributes(request.getAttributes());
        complianceProfileRuleRepository.save(complianceProfileRule);

        return getProviderRule(complianceProfile.getUuid(), complianceProfile.getName(), connectorUuid, request.getKind(), request.getRuleUuid(), complianceProfileRule.getAttributes());
    }

    @Override
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.UPDATE)
    public ComplianceProfileRuleDto removeRule(SecuredUUID uuid, ComplianceRuleDeletionRequestDto request) throws NotFoundException, ConnectorException {
        ComplianceProfile complianceProfile = complianceProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(ComplianceProfile.class, uuid));

        UUID connectorUuid = UUID.fromString(request.getConnectorUuid());
        ConnectorDto connectorDto = getValidatedComplianceProvider(connectorUuid, request.getKind());

        ComplianceProfileRule complianceProfileRule = complianceProfileRuleRepository.findByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(uuid.getValue(), connectorUuid, request.getKind(), UUID.fromString(request.getRuleUuid())).orElse(null);
        if (complianceProfileRule == null) {
            throw new NotFoundException("Compliance rule with UUID %s from provider '%s' is not associated with compliance profile".formatted(request.getRuleUuid(), connectorDto.getName()));
        }
        complianceProfileRuleRepository.deleteByComplianceProfileUuidAndConnectorUuidAndKindAndComplianceRuleUuid(uuid.getValue(), connectorUuid, request.getKind(), UUID.fromString(request.getRuleUuid()));
        return getProviderRule(complianceProfile.getUuid(), complianceProfile.getName(), UUID.fromString(request.getConnectorUuid()), request.getKind(), request.getRuleUuid(), complianceProfileRule.getAttributes());
    }

    private ComplianceProfileRuleDto getProviderRule(UUID complianceProfileUuid, String complianceProfileName, UUID connectorUuid, String kind, String ruleUuid, List<RequestAttribute> requestAttributes) throws NotFoundException, ConnectorException {
        ConnectorDto connectorDto = getValidatedComplianceProvider(connectorUuid, kind);

        ComplianceProfileRuleDto resultRule = null;
        var providerRules = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceRules(connectorDto, kind, null);
        for (var providerRule : providerRules) {
            if (providerRule.getUuid().equals(ruleUuid)) {
                resultRule = new ComplianceProfileRuleDto();
                resultRule.setUuid(ruleUuid);
                resultRule.setName(providerRule.getName());
                resultRule.setDescription(providerRule.getDescription());
                resultRule.setConnectorUuid(connectorDto.getUuid());
                resultRule.setConnectorName(connectorDto.getName());
                resultRule.setKind(kind);
                resultRule.setGroupUuid(providerRule.getGroupUuid());
                resultRule.setCertificateType(providerRule.getCertificateType());
                resultRule.setAttributes(attributeEngine.getRequestDataAttributesContent(providerRule.getAttributes(), requestAttributes));
                resultRule.setComplianceProfileUuid(complianceProfileUuid.toString());
                resultRule.setComplianceProfileName(complianceProfileName);
                break;
            }
        }
        if (resultRule == null) {
            throw new NotFoundException("Compliance rule with UUID %s not found in provider %s".formatted(ruleUuid, connectorDto.getName()));
        }
        return resultRule;
    }

    @Override
    public ComplianceProfileDto addGroup(SecuredUUID uuid, ComplianceGroupRequestDto request) throws NotFoundException, ConnectorException {
        var requestDto = new com.czertainly.api.model.client.compliance.v2.ComplianceProfileGroupsPatchRequestDto();
        requestDto.setRemoval(false);
        requestDto.setGroupUuid(UUID.fromString(request.getGroupUuid()));
        requestDto.setConnectorUuid(UUID.fromString(request.getConnectorUuid()));
        requestDto.setKind(request.getKind());
        complianceProfileServiceV2.patchComplianceProfileGroups(uuid, requestDto);

        return getComplianceProfile(uuid);
    }

    @Override
    public ComplianceProfileDto removeGroup(SecuredUUID uuid, ComplianceGroupRequestDto request) throws NotFoundException, ConnectorException {
        var requestDto = new com.czertainly.api.model.client.compliance.v2.ComplianceProfileGroupsPatchRequestDto();
        requestDto.setRemoval(true);
        requestDto.setGroupUuid(UUID.fromString(request.getGroupUuid()));
        requestDto.setConnectorUuid(UUID.fromString(request.getConnectorUuid()));
        requestDto.setKind(request.getKind());
        complianceProfileServiceV2.patchComplianceProfileGroups(uuid, requestDto);

        return getComplianceProfile(uuid);
    }

    @Override
    public void deleteComplianceProfile(SecuredUUID uuid) throws NotFoundException, ValidationException {
        complianceProfileServiceV2.deleteComplianceProfile(uuid);
    }

    @Override
    public List<BulkActionMessageDto> bulkDeleteComplianceProfiles(List<SecuredUUID> uuids) throws NotFoundException, ValidationException {
        return complianceProfileServiceV2.bulkDeleteComplianceProfiles(uuids);
    }

    @Override
    public List<BulkActionMessageDto> forceDeleteComplianceProfiles(List<SecuredUUID> uuids) {
        return complianceProfileServiceV2.forceDeleteComplianceProfiles(uuids);
    }

    @Override
    public List<ComplianceRulesListResponseDto> getComplianceRules(String complianceProviderUuid, String kind, List<CertificateType> certificateType) throws NotFoundException, ConnectorException {
        boolean withKind = kind != null && !kind.isBlank();
        boolean withComplianceProvider = complianceProviderUuid != null && !complianceProviderUuid.isBlank();
        List<String> certificateTypes = certificateType == null || certificateType.isEmpty() ? List.of() : certificateType.stream().map(CertificateType::toString).toList();
        List<ConnectorDto> complianceProviders = new ArrayList<>();
        if (withComplianceProvider) {
            Connector connector = connectorRepository.findByUuid(UUID.fromString(complianceProviderUuid)).orElseThrow(() -> new NotFoundException(Connector.class, complianceProviderUuid));
            complianceProviders.add(connector.mapToDto());
        } else {
            complianceProviders = withKind
                    ? connectorRepository.findConnectedByFunctionGroupCodeAndKind(FunctionGroupCode.COMPLIANCE_PROVIDER, kind).stream().map(Connector::mapToDto).toList()
                    : connectorRepository.findConnectedByFunctionGroupCode(FunctionGroupCode.COMPLIANCE_PROVIDER).stream().map(Connector::mapToDto).toList();
        }

        List<ComplianceRulesListResponseDto> providersRules = new ArrayList<>();
        for (ConnectorDto connectorDto : complianceProviders) {
            List<String> providerKinds = new ArrayList<>();
            if (withKind) {
                providerKinds.add(kind);
            } else {
                connectorDto.getFunctionGroups().stream().filter(fgDto -> fgDto.getFunctionGroupCode() == FunctionGroupCode.COMPLIANCE_PROVIDER).findFirst().ifPresent(fg -> providerKinds.addAll(fg.getKinds()));
            }

            for (String providerKind : providerKinds) {
                ComplianceRulesListResponseDto providerRules = new ComplianceRulesListResponseDto();
                providerRules.setConnectorUuid(connectorDto.getUuid());
                providerRules.setConnectorName(connectorDto.getName());
                providerRules.setKind(providerKind);
                List<ComplianceRulesResponseDto> rules = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceRules(connectorDto, providerKind, certificateTypes);

                providerRules.setRules(rules.stream().map(pr -> {
                    ComplianceRulesResponseDto ruleDto = new ComplianceRulesResponseDto();
                    ruleDto.setUuid(pr.getUuid());
                    ruleDto.setName(pr.getName());
                    ruleDto.setDescription(pr.getDescription());
                    ruleDto.setGroupUuid(pr.getGroupUuid());
                    ruleDto.setCertificateType(pr.getCertificateType());
                    ruleDto.setAttributes(pr.getAttributes());
                    return ruleDto;
                }).toList());

                providersRules.add(providerRules);
            }
        }

        return providersRules;
    }

    @Override
    public List<ComplianceGroupsListResponseDto> getComplianceGroups(String complianceProviderUuid, String kind) throws NotFoundException, ConnectorException {
        boolean withKind = kind != null && !kind.isBlank();
        boolean withComplianceProvider = complianceProviderUuid != null && !complianceProviderUuid.isBlank();
        List<ConnectorDto> complianceProviders = new ArrayList<>();
        if (withComplianceProvider) {
            Connector connector = connectorRepository.findByUuid(UUID.fromString(complianceProviderUuid)).orElseThrow(() -> new NotFoundException(Connector.class, complianceProviderUuid));
            complianceProviders.add(connector.mapToDto());
        } else {
            complianceProviders = withKind
                    ? connectorRepository.findConnectedByFunctionGroupCodeAndKind(FunctionGroupCode.COMPLIANCE_PROVIDER, kind).stream().map(Connector::mapToDto).toList()
                    : connectorRepository.findConnectedByFunctionGroupCode(FunctionGroupCode.COMPLIANCE_PROVIDER).stream().map(Connector::mapToDto).toList();
        }

        List<ComplianceGroupsListResponseDto> providersGroups = new ArrayList<>();
        for (ConnectorDto connectorDto : complianceProviders) {
            List<String> providerKinds = new ArrayList<>();
            if (withKind) {
                providerKinds.add(kind);
            } else {
                connectorDto.getFunctionGroups().stream().filter(fgDto -> fgDto.getFunctionGroupCode() == FunctionGroupCode.COMPLIANCE_PROVIDER).findFirst().ifPresent(fg -> providerKinds.addAll(fg.getKinds()));
            }

            for (String providerKind : providerKinds) {
                ComplianceGroupsListResponseDto providerGroups = new ComplianceGroupsListResponseDto();
                providerGroups.setConnectorUuid(connectorDto.getUuid());
                providerGroups.setConnectorName(connectorDto.getName());
                providerGroups.setKind(providerKind);
                List<ComplianceGroupsResponseDto> groups = connectorApiFactory.getComplianceApiClient(connectorDto).getComplianceGroups(connectorDto, providerKind);

                providerGroups.setGroups(groups.stream().map(pr -> {
                    ComplianceGroupsResponseDto groupDto = new ComplianceGroupsResponseDto();
                    groupDto.setUuid(pr.getUuid());
                    groupDto.setName(pr.getName());
                    groupDto.setDescription(pr.getDescription());
                    return groupDto;
                }).toList());

                providersGroups.add(providerGroups);
            }
        }

        return providersGroups;
    }

    @Override
    @ExternalAuthorization(resource = Resource.COMPLIANCE_PROFILE, action = ResourceAction.DETAIL)
    public List<SimplifiedRaProfileDto> getAssociatedRAProfiles(SecuredUUID uuid) {
        List<ComplianceProfileAssociation> raProfileAssociations = complianceProfileAssociationRepository.findByComplianceProfileUuidAndResource(uuid.getValue(), Resource.RA_PROFILE);

        List<UUID> raProfileUuids = raProfileAssociations.stream().map(ComplianceProfileAssociation::getObjectUuid).toList();
        return raProfileRepository.findAllByUuidIn(raProfileUuids).stream().map(RaProfile::mapToDtoSimplified).toList();
    }

    @Override
    public void associateProfile(SecuredUUID uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException, AlreadyExistException {
        for (String raProfileUuid : raProfiles.getRaProfileUuids()) {
            complianceProfileServiceV2.associateComplianceProfile(uuid, Resource.RA_PROFILE, UUID.fromString(raProfileUuid));
        }
    }

    @Override
    public void disassociateProfile(SecuredUUID uuid, RaProfileAssociationRequestDto raProfiles) throws NotFoundException {
        for (String raProfileUuid : raProfiles.getRaProfileUuids()) {
            complianceProfileServiceV2.disassociateComplianceProfile(uuid, Resource.RA_PROFILE, UUID.fromString(raProfileUuid));
        }
    }

    @Override
    public void checkCompliance(List<SecuredUUID> uuids) {
        // will be implemented in compliance check V2 rewrite
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return complianceProfileServiceV2.getResourceObjectInternal(objectUuid);
    }

    @Override
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return complianceProfileServiceV2.getResourceObjectExternal(objectUuid);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return complianceProfileServiceV2.listResourceObjects(filter, filters, pagination);
    }

    @Override
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        complianceProfileServiceV2.evaluatePermissionChain(uuid);
    }

    public ConnectorDto getValidatedComplianceProvider(UUID connectorUuid, String kind) throws ValidationException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(connectorUuid).orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        ConnectorDto connectorDto = connector.mapToDto();

        FunctionGroupDto functionGroup = connectorDto.getFunctionGroups().stream().filter(fg -> fg.getFunctionGroupCode().equals(FunctionGroupCode.COMPLIANCE_PROVIDER) && fg.getKinds().contains(kind)).findFirst().orElse(null);
        if (functionGroup == null) {
            throw new ValidationException("Connector '%s' does not implement compliance provider V1 function group with kind '%s'".formatted(connectorDto.getName(), kind));
        }

        return connectorDto;
    }
}
