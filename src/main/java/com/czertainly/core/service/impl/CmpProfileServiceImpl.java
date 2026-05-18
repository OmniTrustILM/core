package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.cmp.CmpProfileEditRequestDto;
import com.czertainly.api.model.client.cmp.CmpProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDto;
import com.czertainly.api.model.core.cmp.CmpProfileDetailDto;
import com.czertainly.api.model.core.cmp.CmpProfileDto;
import com.czertainly.api.model.core.cmp.CmpProfileVariant;
import com.czertainly.api.model.core.cmp.ProtectionMethod;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile_;
import com.czertainly.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.CmpProfileService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import com.czertainly.core.util.CertificateUtil;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.CMP_PROFILE)
@Transactional
public class CmpProfileServiceImpl implements CmpProfileService {

    private static final Logger logger = LoggerFactory.getLogger(CmpProfileServiceImpl.class);

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Injectors
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    private CmpProfileRepository cmpProfileRepository;
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
    public void setCmpProfileRepository(CmpProfileRepository cmpProfileRepository) {
        this.cmpProfileRepository = cmpProfileRepository;
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

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Methods implementations
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.LIST)
    public List<CmpProfileDto> listCmpProfile(SecurityFilter filter) {
        logger.debug("Getting all the CMP Profiles available in the database");
        return cmpProfileRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(CmpProfile::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DETAIL)
    public CmpProfileDetailDto getCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        logger.info("Requesting the details for the CMP Profile with uuid {}", cmpProfileUuid);
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);

        return mapToDetailDto(cmpProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.CREATE)
    public CmpProfileDetailDto createCmpProfile(CmpProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        if (cmpProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("CMP Profile " + request.getName() + " already exists");
        }

        CmpProfile cmpProfile = new CmpProfile();

        // validate and set variant configuration
        validateAndSetVariantConfiguration(cmpProfile, request);

        // validate and set protection methods
        validateAndSetProtectionMethods(cmpProfile, request);

        // validate custom attributes
        attributeEngine.validateCustomAttributesContent(Resource.CMP_PROFILE, request.getCustomAttributes());

        // check if RA Profile is provided
        RaProfile raProfile = getProvidedRaProfile(request);

        // new CMP Profile is disabled by default
        cmpProfile.setEnabled(false);
        cmpProfile.setName(request.getName());
        cmpProfile.setDescription(request.getDescription());
        cmpProfile.setRaProfile(raProfile);
        cmpProfile.setRequestProtectionMethod(request.getRequestProtectionMethod());
        cmpProfile.setResponseProtectionMethod(request.getResponseProtectionMethod());

        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            ProtocolCertificateAssociations certificateAssociation = new ProtocolCertificateAssociations();
            certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
            certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
            certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
            certificateAssociationRepository.save(certificateAssociation);
            cmpProfile.setCertificateAssociations(certificateAssociation);
            cmpProfile.setCertificateAssociationsUuid(certificateAssociation.getUuid());
        }

        cmpProfile = cmpProfileRepository.save(cmpProfile);

        CmpProfileDetailDto dto = updateAndMapDtoAttributes(
                cmpProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(),
                request.getCustomAttributes()
        );

        logger.info("CMP Profile created successfully: name={}, uuid={}", cmpProfile.getName(), cmpProfile.getUuid());

        return dto;
    }

    private static ProtocolCertificateAssociations getCertificateAssociation(CmpProfileEditRequestDto request, CmpProfile cmpProfile) {
        ProtocolCertificateAssociations certificateAssociation = cmpProfile.getCertificateAssociations();
        if (certificateAssociation == null) certificateAssociation = new ProtocolCertificateAssociations();
        certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
        certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
        certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
        return certificateAssociation;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public CmpProfileDetailDto editCmpProfile(SecuredUUID cmpProfileUuid, CmpProfileEditRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);

        // validate and set variant configuration
        validateAndSetVariantConfiguration(cmpProfile, request);

        // validate and set protection methods
        validateAndSetProtectionMethods(cmpProfile, request);

        // validate custom attributes
        attributeEngine.validateCustomAttributesContent(Resource.CMP_PROFILE, request.getCustomAttributes());

        // check if RA Profile is provided
        RaProfile raProfile = getProvidedRaProfile(request);

        // delete old connector data attributes content
        UUID oldConnectorUuid = cmpProfile.getRaProfile() == null ? null : cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();
        if (oldConnectorUuid != null) {
            attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(oldConnectorUuid).operation(AttributeOperation.CERTIFICATE_ISSUE).build());
        }

        cmpProfile.setDescription(request.getDescription());
        cmpProfile.setRaProfile(raProfile);
        cmpProfile.setRequestProtectionMethod(request.getRequestProtectionMethod());
        cmpProfile.setResponseProtectionMethod(request.getResponseProtectionMethod());

        UUID certificateAssociationUuid = null;
        ProtocolCertificateAssociations certificateAssociation = null;
        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            certificateAssociation = getCertificateAssociation(request, cmpProfile);
            certificateAssociationRepository.save(certificateAssociation);
            certificateAssociationUuid = certificateAssociation.getUuid();
        }

        cmpProfile.setCertificateAssociations(certificateAssociation);
        cmpProfile.setCertificateAssociationsUuid(certificateAssociationUuid);

        cmpProfileRepository.save(cmpProfile);

        CmpProfileDetailDto dto = updateAndMapDtoAttributes(
                cmpProfile,
                raProfile,
                request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(),
                request.getCustomAttributes()
        );

        logger.info("CMP Profile updated successfully: name={}, uuid={}", cmpProfile.getName(), cmpProfile.getUuid());

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public void deleteCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException, ValidationException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        deleteCmpProfile(cmpProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            CmpProfile cmpProfile = null;
            try {
                cmpProfile = getCmpProfileEntity(cmpProfileUuid);
                deleteCmpProfile(cmpProfile);
            } catch (Exception e) {
                logger.error(e.getMessage());
                messages.add(BulkActionMessageDto.failure(cmpProfileUuid.toString(), cmpProfile != null ? cmpProfile.getName() : "", e, "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkForceRemoveCmpProfiles(List<SecuredUUID> cmpProfileUuids) throws ValidationException {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            CmpProfile cmpProfile = null;
            try {
                cmpProfile = getCmpProfileEntity(cmpProfileUuid);
                SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithCmpProfile(
                        cmpProfile.getUuid().toString(), SecurityFilter.create());
                // CMP Profile only from allowed ones, but that would make the forbidden RA Profiles point to non-existing CMP Profile.
                raProfileService.bulkRemoveAssociatedCmpProfile(
                        raProfiles.getAll().stream().map(UniquelyIdentifiedAndAudited::getSecuredParentUuid).collect(Collectors.toList()));
                deleteCmpProfile(cmpProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(BulkActionMessageDto.failure(cmpProfileUuid.toString(), cmpProfile != null ? cmpProfile.getName() : "", e, "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void enableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        changeCmpStatus(cmpProfileUuid, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            try {
                changeCmpStatus(cmpProfileUuid, true);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void disableCmpProfile(SecuredUUID cmpProfileUuid) throws NotFoundException {
        changeCmpStatus(cmpProfileUuid, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableCmpProfile(List<SecuredUUID> cmpProfileUuids) {
        for (SecuredUUID cmpProfileUuid : cmpProfileUuids) {
            try {
                changeCmpStatus(cmpProfileUuid, false);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public void updateRaProfile(SecuredUUID cmpProfileUuid, String raProfileUuid) throws NotFoundException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        cmpProfile.setRaProfile(getRaProfile(raProfileUuid));
        cmpProfileRepository.save(cmpProfile);
    }

    @Override
    public List<CertificateDto> listCmpSigningCertificates() {
        return certificateService.listCmpSigningCertificates(SecurityFilter.create());
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return cmpProfileRepository.findResourceObject(objectUuid, CmpProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return cmpProfileRepository.findResourceObject(objectUuid.getValue(), CmpProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return cmpProfileRepository.listResourceObjects(filter, CmpProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CMP_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCmpProfileEntity(uuid);
        // Since there are is no parent to the CMP Profile, exclusive parent permission evaluation need not be done
    }

    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------
    // Helper private methods
    // -----------------------------------------------------------------------------------------------------------------
    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Validate the variant configuration for the CMP Profile
     * @param cmpProfile CMP Profile entity
     * @param request CMP Profile request DTO
     * @throws ValidationException When the variant configuration is not valid
     */
    private void validateAndSetVariantConfiguration(CmpProfile cmpProfile, CmpProfileRequestDto request) throws ValidationException {
        switch (request.getVariant()) {
            case V2 -> {
                // when the response protection method is shared secret, the request protection method must be shared
                // secret, because they share the same secret and the client must know the secret to decrypt
                // the response
                if (request.getResponseProtectionMethod() == ProtectionMethod.SHARED_SECRET &&
                        request.getRequestProtectionMethod() != ProtectionMethod.SHARED_SECRET) {
                    throw new ValidationException(ValidationError.create(
                            "Request protection method for the CMPv2 must be " +
                                    ProtectionMethod.SHARED_SECRET.getCode()) +
                            " when response protection method is " + ProtectionMethod.SHARED_SECRET.getCode());
                }
                // when the request protection method is signature, the response protection method must be signature
                // because the client does not have knowledge of the shared secret
                if (request.getRequestProtectionMethod() == ProtectionMethod.SIGNATURE &&
                        request.getResponseProtectionMethod() != ProtectionMethod.SIGNATURE) {
                    throw new ValidationException(ValidationError.create(
                            "Response protection method for the CMPv2 must be " +
                                    ProtectionMethod.SIGNATURE.getCode()) +
                            " when request protection method is " + ProtectionMethod.SIGNATURE.getCode());
                }
                cmpProfile.setVariant(CmpProfileVariant.V2);
            }
            case V2_3GPP -> {
                if (request.getRequestProtectionMethod() != ProtectionMethod.SIGNATURE) {
                    throw new ValidationException(ValidationError.create(
                            "Request protection method for the 3GPP CMP request must be " +
                                    ProtectionMethod.SIGNATURE.getCode()));
                }
                if (request.getResponseProtectionMethod() != ProtectionMethod.SIGNATURE) {
                    throw new ValidationException(ValidationError.create(
                            "Response protection method for the 3GPP CMP response must be " +
                                    ProtectionMethod.SIGNATURE.getCode()));
                }
                cmpProfile.setVariant(CmpProfileVariant.V2_3GPP);
            }
            case V3 -> throw new ValidationException(ValidationError.create("CMPv3 is not supported yet"));
            default ->
                    throw new ValidationException(ValidationError.create("Variant for the CMP Profile not supported"));
        }
    }

    /**
     * Validate and set the protection methods for the CMP Profile
     * @param cmpProfile CMP Profile entity
     * @param request CMP Profile request DTO
     * @throws NotFoundException When the certificate for signature response protection is not found
     */
    private void validateAndSetProtectionMethods(CmpProfile cmpProfile, CmpProfileRequestDto request) throws NotFoundException {
        // validate and set request protection method
        switch (request.getRequestProtectionMethod()) {
            case SHARED_SECRET -> {
                if (request.getSharedSecret() == null || request.getSharedSecret().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Shared secret cannot be empty"));
                }
                cmpProfile.setSharedSecret(request.getSharedSecret());
            }
            case SIGNATURE -> cmpProfile.setSharedSecret(null);
            default ->
                    throw new ValidationException(ValidationError.create("Protection method for the CMP request not supported"));
        }

        // validate and set response protection method
        switch (request.getResponseProtectionMethod()) {
            case SHARED_SECRET -> cmpProfile.setSigningCertificateUuid(null);
            case SIGNATURE -> {
                if (request.getSigningCertificateUuid() == null || request.getSigningCertificateUuid().isEmpty()) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be empty"));
                }
                Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(request.getSigningCertificateUuid()));
                if (!CertificateUtil.isCertificateCmpAcceptable(certificate)) {
                    throw new ValidationException(ValidationError.create("Signing certificate cannot be used for CMP Profile"));
                }
                cmpProfile.setSigningCertificateUuid(UUID.fromString(request.getSigningCertificateUuid()));
            }
            default ->
                    throw new ValidationException(ValidationError.create("Protection method for the CMP response not supported"));
        }
    }

    /**
     * Get the RA Profile entity from the provided RA Profile UUID, if available
     * @param request CMP Profile request DTO
     * @return RA Profile entity
     * @throws ConnectorException When the RA Profile is not found, or connector is not available
     * @throws AttributeException When the attributes are not valid
     */
    private RaProfile getProvidedRaProfile(CmpProfileRequestDto request) throws AttributeException, ConnectorException, NotFoundException {
        // check if RA Profile is provided
        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService.mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }
        return raProfile;
    }

    private CmpProfileDetailDto mapToDetailDto(CmpProfile cmpProfile) {
        CmpProfileDetailDto dto = cmpProfile.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CMP_PROFILE, cmpProfile.getUuid()));
        if (cmpProfile.getRaProfile() != null) {
            dto.setIssueCertificateAttributes(
                    attributeEngine.getObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build()
                    )
            );
            dto.setRevokeCertificateAttributes(
                    attributeEngine.getObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build()
                    )
            );
        }

        if (cmpProfile.getCertificateAssociations() != null) {
            dto.setCertificateAssociations(cmpProfile.getCertificateAssociations().mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine.loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }

        return dto;
    }

    private CmpProfileDetailDto updateAndMapDtoAttributes(CmpProfile cmpProfile, RaProfile raProfile,
                                     List<RequestAttribute> issueCertificateAttributes,
                                     List<RequestAttribute> revokeCertificateAttributes,
                                     List<RequestAttribute> customAttributes) throws NotFoundException, AttributeException {
        CmpProfileDetailDto dto = cmpProfile.mapToDetailDto();
        dto.setCustomAttributes(
                attributeEngine.updateObjectCustomAttributesContent(
                        Resource.CMP_PROFILE,
                        cmpProfile.getUuid(),
                        customAttributes
                )
        );
        if (raProfile != null) {
            dto.setIssueCertificateAttributes(
                    attributeEngine.updateObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build(),
                            issueCertificateAttributes
                    )
            );
            dto.setRevokeCertificateAttributes(
                    attributeEngine.updateObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build(),
                            revokeCertificateAttributes
                    )
            );
        }

        if (cmpProfile.getCertificateAssociations() != null) {
            dto.setCertificateAssociations(cmpProfile.getCertificateAssociations().mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine.loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }

        return dto;
    }

    private CmpProfile getCmpProfileEntity(SecuredUUID cmpProfileUuid) throws NotFoundException {
        return cmpProfileRepository.findByUuid(cmpProfileUuid).orElseThrow(() -> new NotFoundException(CmpProfile.class, cmpProfileUuid));
    }

    private RaProfile getRaProfile(String raProfileUuid) throws NotFoundException {
        return raProfileService.getRaProfileEntity(SecuredUUID.fromString(raProfileUuid));
    }

    private void deleteCmpProfile(CmpProfile cmpProfile) {
        SecuredList<RaProfile> raProfiles = raProfileService.listRaProfilesAssociatedWithCmpProfile(
                cmpProfile.getUuid().toString(), SecurityFilter.create());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(
                            String.format(
                                    "Cannot remove as there are associated RA Profiles (%d): %s",
                                    raProfiles.size(),
                                    raProfiles.getAllowed().stream().map(RaProfile::getName).collect(Collectors.joining(","))
                            )
                    )
            );
        } else {
            attributeEngine.deleteObjectAttributeContent(Resource.CMP_PROFILE, cmpProfile.getUuid());
            cmpProfileRepository.delete(cmpProfile);
        }
    }

    private void changeCmpStatus(SecuredUUID cmpProfileUuid, boolean enabled) throws NotFoundException {
        CmpProfile cmpProfile = getCmpProfileEntity(cmpProfileUuid);
        cmpProfile.setEnabled(enabled);
        cmpProfileRepository.save(cmpProfile);
    }

}
