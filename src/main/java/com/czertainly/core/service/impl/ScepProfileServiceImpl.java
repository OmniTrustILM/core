package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.scep.ScepProfileEditRequestDto;
import com.czertainly.api.model.client.scep.ScepProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDto;
import com.czertainly.api.model.core.scep.ScepProfileDetailDto;
import com.czertainly.api.model.core.scep.ScepProfileDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.entity.scep.ScepProfile_;
import com.czertainly.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.ValidatorUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.SCEP_PROFILE)
@Transactional
public class ScepProfileServiceImpl implements ScepProfileService {

    private static final Logger logger = LoggerFactory.getLogger(ScepProfileServiceImpl.class);
    private final ScepProfileRepository scepProfileRepository;
    private RaProfileService raProfileService;
    private ExtendedAttributeService extendedAttributeService;
    private CertificateService certificateService;
    private AttributeEngine attributeEngine;
    private ProtocolCertificateAssociationsRepository certificateAssociationRepository;

    @Autowired
    public void setCertificateAssociationRepository(ProtocolCertificateAssociationsRepository certificateAssociationRepository) {
        this.certificateAssociationRepository = certificateAssociationRepository;
    }

    @Autowired
    public ScepProfileServiceImpl(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileRepository) {
        this.raProfileService = raProfileRepository;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.LIST)
    public List<ScepProfileDto> listScepProfile(SecurityFilter filter) {
        logger.debug("Getting all the SCEP Profiles available in the database");
        return scepProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(ScepProfile::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.DETAIL)
    public ScepProfileDetailDto getScepProfile(SecuredUUID uuid) throws NotFoundException {
        logger.info("Requesting the details for the SCEP Profile with uuid {}", uuid);
        ScepProfile scepProfile = getScepProfileEntity(uuid);

        return mapToDetailDto(scepProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.CREATE)
    public ScepProfileDetailDto createScepProfile(ScepProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        if (request.getName() == null || request.getName().isEmpty()) {
            throw new ValidationException(ValidationError.create("Name cannot be empty"));
        }
        if (ValidatorUtil.containsUnreservedCharacters(request.getName())) {
            throw new ValidationException(ValidationError.create("Name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
        }
        if (scepProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("SCEP Profile with same name already exists");
        }
        if (request.getCaCertificateUuid() == null || request.getCaCertificateUuid().isEmpty()) {
            throw new ValidationException(ValidationError.create("CA Certificate cannot be empty"));
        }

        boolean intuneEnabled = Boolean.TRUE.equals(request.getEnableIntune());
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(request.getCaCertificateUuid()));
        if (!CertificateUtil.isCertificateScepCaCertAcceptable(certificate, intuneEnabled)) {
            throw new ValidationException(ValidationError.create("CA Certificate is not acceptable as SCEP CA certificate for this profile"));
        }

        if (intuneEnabled && (request.getIntuneTenant() == null || request.getIntuneApplicationId() == null || request.getIntuneApplicationKey() == null)) {
            throw new ValidationException(ValidationError.create("Invalid Intune configuration. Missing Intune tenant and/or intune app identification"));
        }

        RaProfile raProfile = null;
        attributeEngine.validateCustomAttributesContent(Resource.SCEP_PROFILE, request.getCustomAttributes());
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());

            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
        }

        logger.info("Creating a new SCEP Profile");

        ScepProfile scepProfile = new ScepProfile();
        scepProfile.setEnabled(false);
        scepProfile.setName(request.getName());
        scepProfile.setDescription(request.getDescription());
        // The value 0 will be considered as half life of the certificate for SCEP protocol
        scepProfile.setRenewalThreshold(request.getRenewalThreshold());
        scepProfile.setIncludeCaCertificateChain(request.isIncludeCaCertificateChain());
        scepProfile.setIncludeCaCertificate(request.isIncludeCaCertificate());
        scepProfile.setChallengePassword(request.getChallengePassword());
        scepProfile.setRequireManualApproval(false);
        scepProfile.setCaCertificateUuid(UUID.fromString(request.getCaCertificateUuid()));
        scepProfile.setIntuneEnabled(intuneEnabled);
        scepProfile.setIntuneTenant(request.getIntuneTenant());
        scepProfile.setIntuneApplicationId(request.getIntuneApplicationId());
        scepProfile.setIntuneApplicationKey(request.getIntuneApplicationKey());
        scepProfile.setRaProfile(raProfile);

        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            ProtocolCertificateAssociations certificateAssociation = new ProtocolCertificateAssociations();
            certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
            certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
            certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
            certificateAssociationRepository.save(certificateAssociation);
            scepProfile.setCertificateAssociations(certificateAssociation);
            scepProfile.setCertificateAssociationsUuid(certificateAssociation.getUuid());
        }

        scepProfile = scepProfileRepository.save(scepProfile);

        return updateAndMapDtoAttributes(
                scepProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getCustomAttributes()
        );
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.UPDATE)
    public ScepProfileDetailDto editScepProfile(SecuredUUID uuid, ScepProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        if (request.getCaCertificateUuid() == null || request.getCaCertificateUuid().isEmpty()) {
            throw new ValidationException(ValidationError.create("CA Certificate cannot be empty"));
        }

        boolean intuneEnabled = Boolean.TRUE.equals(request.getEnableIntune());
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(request.getCaCertificateUuid()));
        if(!CertificateUtil.isCertificateScepCaCertAcceptable(certificate, intuneEnabled)) {
            throw new ValidationException(ValidationError.create("CA Certificate is not acceptable as SCEP CA certificate for this profile"));
        }

        if (intuneEnabled && (request.getIntuneTenant() == null || request.getIntuneApplicationId() == null || request.getIntuneApplicationKey() == null)) {
            throw new ValidationException(ValidationError.create("Invalid Intune configuration. Missing Intune tenant and/or intune app identification"));
        }

        attributeEngine.validateCustomAttributesContent(Resource.SCEP_PROFILE, request.getCustomAttributes());

        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
        }

        ScepProfile scepProfile = getScepProfileEntity(uuid);
        scepProfile.setRequireManualApproval(false);
        scepProfile.setIncludeCaCertificate(request.isIncludeCaCertificate());
        scepProfile.setIncludeCaCertificateChain(request.isIncludeCaCertificateChain());
        if (request.getRenewalThreshold() != null) scepProfile.setRenewalThreshold(request.getRenewalThreshold());
        if (scepProfile.getChallengePassword() != null)
            scepProfile.setChallengePassword(request.getChallengePassword());

        // delete old connector data attributes content
        UUID oldConnectorUuid = scepProfile.getRaProfile() == null ? null : scepProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();
        if (oldConnectorUuid != null) {
            attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, ObjectAttributeContentInfo.builder(Resource.SCEP_PROFILE, scepProfile.getUuid()).connector(oldConnectorUuid).operation(AttributeOperation.CERTIFICATE_ISSUE).build());
        }

        scepProfile.setRaProfile(raProfile);
        scepProfile.setDescription(request.getDescription());
        scepProfile.setCaCertificateUuid(UUID.fromString(request.getCaCertificateUuid()));
        scepProfile.setIntuneEnabled(intuneEnabled);
        scepProfile.setIntuneTenant(request.getIntuneTenant());
        scepProfile.setIntuneApplicationId(request.getIntuneApplicationId());
        scepProfile.setIntuneApplicationKey(request.getIntuneApplicationKey());

        UUID certificateAssociationUuid = null;
        ProtocolCertificateAssociations certificateAssociation = null;
        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            certificateAssociation = getCertificateAssociation(request, scepProfile);
            certificateAssociationRepository.save(certificateAssociation);
            certificateAssociationUuid = certificateAssociation.getUuid();
        }

        scepProfile.setCertificateAssociations(certificateAssociation);
        scepProfile.setCertificateAssociationsUuid(certificateAssociationUuid);

        scepProfile = scepProfileRepository.save(scepProfile);

        return updateAndMapDtoAttributes(
                scepProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getCustomAttributes()
        );
    }

    private ScepProfileDetailDto mapToDetailDto(ScepProfile scepProfile) {
        ScepProfileDetailDto dto = scepProfile.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.SCEP_PROFILE, scepProfile.getUuid()));
        if (scepProfile.getRaProfile() != null) {
            dto.setIssueCertificateAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SCEP_PROFILE, scepProfile.getUuid()).connector(scepProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build()));
        }
        if (scepProfile.getCertificateAssociations() != null) {
            dto.setCertificateAssociations(scepProfile.getCertificateAssociations().mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine.loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }
        return dto;
    }

    private ScepProfileDetailDto updateAndMapDtoAttributes(ScepProfile scepProfile, RaProfile raProfile,
                                                     List<RequestAttribute> issueCertificateAttributes,
                                                     List<RequestAttribute> customAttributes) throws NotFoundException, AttributeException {
        ScepProfileDetailDto dto = scepProfile.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.SCEP_PROFILE, scepProfile.getUuid(), customAttributes));
        if (raProfile != null) {
            dto.setIssueCertificateAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SCEP_PROFILE, scepProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build(), issueCertificateAttributes));
        }
        if (scepProfile.getCertificateAssociations() != null) {
            dto.setCertificateAssociations(scepProfile.getCertificateAssociations().mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine.loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }

        return dto;
    }

    private static ProtocolCertificateAssociations getCertificateAssociation(ScepProfileEditRequestDto request, ScepProfile scepProfile) {
        ProtocolCertificateAssociations certificateAssociation = scepProfile.getCertificateAssociations();
        if (certificateAssociation == null) certificateAssociation = new ProtocolCertificateAssociations();
        certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
        certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
        certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
        return certificateAssociation;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.DELETE)
    public void deleteScepProfile(SecuredUUID uuid) throws NotFoundException, ValidationException {
        ScepProfile scepProfile = getScepProfileEntity(uuid);
        deleteScepProfile(scepProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.ENABLE)
    public void enableScepProfile(SecuredUUID uuid) throws NotFoundException {
        enable(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.ENABLE)
    public void disableScepProfile(SecuredUUID uuid) throws NotFoundException {
        disable(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableScepProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                enable(uuid);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableScepProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                disable(uuid);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteScepProfile(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            ScepProfile scepProfile = null;
            try {
                scepProfile = getScepProfileEntity(uuid);
                deleteScepProfile(scepProfile);
            } catch (Exception e) {
                logger.error(e.getMessage());
                messages.add(BulkActionMessageDto.failure(uuid.toString(), scepProfile != null ? scepProfile.getName() : "", e, "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.UPDATE)
    public void updateRaProfile(SecuredUUID uuid, String raProfileUuid) throws NotFoundException {
        ScepProfile scepProfile = getScepProfileEntity(uuid);
        scepProfile.setRaProfile(getRaProfile(raProfileUuid));
        scepProfileRepository.save(scepProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkForceRemoveScepProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            ScepProfile scepProfile = null;
            try {
                scepProfile = getScepProfileEntity(uuid);
                SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithScepProfile(scepProfile.getUuid().toString(), SecurityFilter.create());
                // SCEP profile only from allowed ones, but that would make the forbidden ra profiles point to nonexistent SCEP profile.
                raProfileService.bulkRemoveAssociatedScepProfile(raProfiles.getAll().stream().map(UniquelyIdentifiedAndAudited::getSecuredParentUuid).collect(Collectors.toList()));
                deleteScepProfile(scepProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(BulkActionMessageDto.failure(uuid.toString(), scepProfile != null ? scepProfile.getName() : "", e, "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return scepProfileRepository.findResourceObject(objectUuid, ScepProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return scepProfileRepository.listResourceObjects(filter, ScepProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCEP_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getScepProfileEntity(uuid);
        // Since there are is no parent to the SCEP Profile, exclusive parent permission evaluation need not be done
    }

    @Override
    public List<CertificateDto> listScepCaCertificates(boolean intuneEnabled) {
        return certificateService.listScepCaCertificates(SecurityFilter.create(), intuneEnabled);
    }

    private RaProfile getRaProfile(String uuid) throws NotFoundException {
        return raProfileService.getRaProfileEntity(SecuredUUID.fromString(uuid));
    }

    private ScepProfile getScepProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return scepProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(ScepProfile.class, uuid));
    }

    private void enable(SecuredUUID uuid) throws NotFoundException {
        ScepProfile scepProfile = getScepProfileEntity(uuid);
        scepProfile.setEnabled(true);
        scepProfileRepository.save(scepProfile);
    }

    private void disable(SecuredUUID uuid) throws NotFoundException {
        ScepProfile scepProfile = getScepProfileEntity(uuid);
        scepProfile.setEnabled(false);
        scepProfileRepository.save(scepProfile);
    }

    private void deleteScepProfile(ScepProfile scepProfile) {
        SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithScepProfile(scepProfile.getUuid().toString(), SecurityFilter.create());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(
                            String.format(
                                    "Dependent SCEP Profiles (%d): %s",
                                    raProfiles.size(),
                                    raProfiles.getAllowed().stream().map(RaProfile::getName).collect(Collectors.joining(","))
                            )
                    )
            );
        } else {
            attributeEngine.deleteObjectAttributeContent(Resource.SCEP_PROFILE, scepProfile.getUuid());
            scepProfileRepository.delete(scepProfile);
        }
    }
}
