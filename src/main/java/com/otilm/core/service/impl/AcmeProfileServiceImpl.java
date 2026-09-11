package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.acme.AcmeProfileEditRequestDto;
import com.otilm.api.model.client.acme.AcmeProfileRequestDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.acme.AcmeEabKeyDto;
import com.otilm.api.model.core.acme.AcmeProfileDto;
import com.otilm.api.model.core.acme.AcmeProfileListDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile_;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AcmeProfileExternalService;
import com.otilm.core.service.AcmeProfileInternalService;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.service.acme.eab.AcmeEabKeys;
import com.otilm.core.service.model.SecuredList;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.util.ValidatorUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service(Resource.Codes.ACME_PROFILE)
@Transactional
public class AcmeProfileServiceImpl implements AcmeProfileExternalService, AcmeProfileInternalService {

    private static final Logger logger = LoggerFactory.getLogger(AcmeProfileServiceImpl.class);
    private final AcmeProfileRepository acmeProfileRepository;
    private AcmeAccountRepository acmeAccountRepository;
    private RaProfileInternalService raProfileService;
    private ExtendedAttributeService extendedAttributeService;
    private AttributeEngine attributeEngine;
    private ProtocolCertificateAssociationsRepository certificateAssociationRepository;

    private CommentInternalService commentService;
    private SecretRepository secretRepository;
    private AuthorizationEnforcer authorizationEnforcer;

    @Autowired
    public void setCommentService(CommentInternalService commentService) {
        this.commentService = commentService;
    }

    @Autowired
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Autowired
    public void setCertificateAssociationRepository(
            ProtocolCertificateAssociationsRepository certificateAssociationRepository) {
        this.certificateAssociationRepository = certificateAssociationRepository;
    }

    @Autowired
    public AcmeProfileServiceImpl(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Autowired
    public void setAcmeAccountRepository(AcmeAccountRepository acmeAccountRepository) {
        this.acmeAccountRepository = acmeAccountRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setRaProfileService(RaProfileInternalService raProfileRepository) {
        this.raProfileService = raProfileRepository;
    }

    @Autowired
    public void setExtendedAttributeService(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.LIST)
    public List<AcmeProfileListDto> listAcmeProfile(SecurityFilter filter) {
        logger.debug("Getting all the ACME Profiles available in the database");
        return acmeProfileRepository
                .findUsingSecurityFilter(filter)
                .stream()
                .map(AcmeProfile::mapToDtoSimple)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DETAIL)
    public AcmeProfileDto getAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        logger.info("Requesting the details for the ACME Profile with uuid {}", uuid);
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);

        return mapToDetailDto(acmeProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.CREATE)
    public AcmeProfileDto createAcmeProfile(AcmeProfileRequestDto request) throws AlreadyExistException,
            ValidationException, ConnectorException, AttributeException, NotFoundException {
        if (request.getName() == null || request.getName().isEmpty()) {
            throw new ValidationException(ValidationError.create("Name cannot be empty"));
        }
        if (ValidatorUtil.containsUnreservedCharacters(request.getName())) {
            throw new ValidationException(ValidationError
                    .create("Name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
        }
        if (request.getValidity() != null && request.getValidity() < 0) {
            throw new ValidationException(ValidationError.create("Order Validity cannot be less than 0"));
        }
        if (request.getRetryInterval() != null && request.getRetryInterval() < 0) {
            throw new ValidationException(ValidationError.create("Retry Interval cannot be less than 0"));
        }

        logger.info("Creating a new ACME Profile");

        if (acmeProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("ACME Profile with same name already exists");
        }

        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null && !request.getRaProfileUuid().isEmpty()) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            if (ValidatorUtil.containsUnreservedCharacters(raProfile.getName())) {
                throw new ValidationException(ValidationError
                        .create("RA Profile name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
            }
            extendedAttributeService
                    .mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService
                    .mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        attributeEngine.validateCustomAttributesContent(Resource.ACME_PROFILE, request.getCustomAttributes());

        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setEnabled(false);
        acmeProfile.setName(request.getName());
        acmeProfile.setDescription(request.getDescription());
        acmeProfile.setDnsResolverIp(request.getDnsResolverIp());
        acmeProfile.setDnsResolverPort(request.getDnsResolverPort());
        acmeProfile.setRetryInterval(Optional.ofNullable(request.getRetryInterval()).orElse(36000));
        acmeProfile.setValidity(Optional.ofNullable(request.getValidity()).orElse(30));
        acmeProfile.setWebsite(request.getWebsiteUrl());
        acmeProfile.setTermsOfServiceUrl(request.getTermsOfServiceUrl());
        acmeProfile.setRequireContact(request.isRequireContact());
        acmeProfile.setRequireTermsOfService(request.isRequireTermsOfService());
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setEabSecretUuids(resolveEabSecrets(request.getEabSecretUuids()));
        requireTermsUrlWhenAgreementIsRequired(acmeProfile);
        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            ProtocolCertificateAssociations certificateAssociation = new ProtocolCertificateAssociations();
            certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
            certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
            certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
            certificateAssociationRepository.save(certificateAssociation);
            acmeProfile.setCertificateAssociations(certificateAssociation);
            acmeProfile.setCertificateAssociationsUuid(certificateAssociation.getUuid());
        }
        acmeProfile = acmeProfileRepository.save(acmeProfile);

        return updateAndMapDtoAttributes(acmeProfile, raProfile, request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(), request.getCustomAttributes());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public AcmeProfileDto editAcmeProfile(SecuredUUID uuid, AcmeProfileEditRequestDto request)
            throws ConnectorException, AttributeException, NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        attributeEngine.validateCustomAttributesContent(Resource.ACME_PROFILE, request.getCustomAttributes());

        if (request.isRequireContact() != null) {
            acmeProfile.setRequireContact(request.isRequireContact());
        }
        if (request.isRequireTermsOfService() != null) {
            acmeProfile.setRequireTermsOfService(request.isRequireTermsOfService());
        }
        if (request.isTermsOfServiceChangeDisable() != null) {
            acmeProfile.setDisableNewOrders(request.isTermsOfServiceChangeDisable());
        }

        RaProfile raProfile = null;
        if (request.getRaProfileUuid() != null) {
            raProfile = getRaProfile(request.getRaProfileUuid());
            if (ValidatorUtil.containsUnreservedCharacters(raProfile.getName())) {
                throw new ValidationException(ValidationError
                        .create("RA Profile name can contain only unreserved URI characters (alphanumeric, hyphen, period, underscore, and tilde)"));
            }
            extendedAttributeService
                    .mergeAndValidateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
            extendedAttributeService
                    .mergeAndValidateRevokeAttributes(raProfile, request.getRevokeCertificateAttributes());
        }

        if (raProfile == null
                && acmeAccountRepository.existsByAcmeProfileUuidAndIsDefaultRaProfileTrue(acmeProfile.getUuid())) {
            throw new ValidationException(ValidationError
                    .create("Cannot remove the RA Profile from ACME Profile '" + acmeProfile.getName() + "' because "
                            + "there are existing ACME accounts registered under this profile. "
                            + "Removing the RA Profile would invalidate those accounts."));
        }

        // delete old connector data attributes content
        UUID oldConnectorUuid = acmeProfile.getRaProfile() == null
                ? null
                : acmeProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid();
        if (oldConnectorUuid != null) {
            attributeEngine
                    .deleteOperationObjectAttributesContent(AttributeType.DATA,
                            ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(oldConnectorUuid)
                                    .operation(AttributeOperation.CERTIFICATE_ISSUE)
                                    .build());
            attributeEngine
                    .deleteOperationObjectAttributesContent(AttributeType.DATA,
                            ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(oldConnectorUuid)
                                    .operation(AttributeOperation.CERTIFICATE_REVOKE)
                                    .build());
        }

        acmeProfile.setRaProfile(raProfile);

        acmeProfile.setDescription(request.getDescription());

        acmeProfile.setDnsResolverIp(request.getDnsResolverIp());
        acmeProfile.setDnsResolverPort(request.getDnsResolverPort());

        if (request.getRetryInterval() != null) {
            if (request.getRetryInterval() < 0) {
                throw new ValidationException(ValidationError.create("Retry Interval cannot be less than 0"));
            }
            acmeProfile.setRetryInterval(request.getRetryInterval());
        } else {
            acmeProfile.setRetryInterval(null);
        }
        if (request.getValidity() != null) {
            if (request.getValidity() < 0) {
                throw new ValidationException(ValidationError.create("Order Validity cannot be less than 0"));
            }
            acmeProfile.setValidity(request.getValidity());
        } else {
            acmeProfile.setValidity(null);
        }
        acmeProfile.setTermsOfServiceUrl(request.getTermsOfServiceUrl());
        acmeProfile.setWebsite(request.getWebsiteUrl());
        acmeProfile.setTermsOfServiceChangeUrl(request.getTermsOfServiceChangeUrl());
        if (request.getEabSecretUuids() != null) {
            acmeProfile.setEabSecretUuids(resolveEabSecrets(request.getEabSecretUuids()));
        }
        requireTermsUrlWhenAgreementIsRequired(acmeProfile);

        UUID certificateAssociationUuid = null;
        ProtocolCertificateAssociations certificateAssociation = null;
        if (request.getCertificateAssociations() != null && !request.getCertificateAssociations().isEmpty()) {
            certificateAssociation = getCertificateAssociation(request, acmeProfile);
            certificateAssociationRepository.save(certificateAssociation);
            certificateAssociationUuid = certificateAssociation.getUuid();
        }
        acmeProfile.setCertificateAssociations(certificateAssociation);
        acmeProfile.setCertificateAssociationsUuid(certificateAssociationUuid);

        acmeProfile = acmeProfileRepository.save(acmeProfile);

        if (raProfile != null) {
            // Keep as the last because it will flush and evict all entities from the Hibernate first-level cache.
            acmeAccountRepository.updateRaProfileForDefaultAccounts(acmeProfile.getUuid(), raProfile.getUuid());
        }

        return updateAndMapDtoAttributes(acmeProfile, raProfile, request.getIssueCertificateAttributes(),
                request.getRevokeCertificateAttributes(), request.getCustomAttributes());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.CREATE)
    public AcmeEabKeyDto generateEabKey() {
        AcmeEabKeyDto dto = new AcmeEabKeyDto();
        dto.setKey(AcmeEabKeys.generate());
        return dto;
    }

    /**
     * Registering a secret as a binding key delegates a read of its content to the platform, which then performs that
     * read on every newAccount without a caller to authorize. The operator doing the registering must therefore be able
     * to perform that read themselves, which takes both of the permissions the read is gated on: the content permission
     * on the secret, and membership of the vault profile it is sourced from. Checking only the first would let an
     * operator who cannot read a secret still put it in charge of a profile.
     * <p>
     * Every UUID must also name a secret that exists, so a profile cannot advertise externalAccountRequired against a
     * key the platform could never read. Duplicates are folded away; order is not meaningful.
     */
    private List<UUID> resolveEabSecrets(List<UUID> requested) {
        if (requested == null || requested.isEmpty()) {
            return new ArrayList<>();
        }
        List<UUID> distinct = requested.stream().filter(Objects::nonNull).distinct().toList();
        // Before the lookup, so a caller who may not read secrets at all learns nothing about which UUIDs exist.
        authorizationEnforcer
                .enforce(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT,
                        distinct.stream().map(SecuredUUID::fromUUID).toList());

        List<Secret> secrets = secretRepository.findByUuidIn(distinct);
        Set<UUID> found = secrets.stream().map(UniquelyIdentifiedAndAudited::getUuid).collect(Collectors.toSet());
        String missing = distinct
                .stream()
                .filter(secretUuid -> !found.contains(secretUuid))
                .map(UUID::toString)
                .collect(Collectors.joining(", "));
        if (!missing.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create("External Account Binding secrets not found: %s".formatted(missing)));
        }

        authorizationEnforcer
                .enforce(Resource.VAULT_PROFILE, ResourceAction.MEMBERS,
                        secrets
                                .stream()
                                .map(Secret::getSourceVaultProfileUuid)
                                .filter(Objects::nonNull)
                                .distinct()
                                .map(SecuredUUID::fromUUID)
                                .toList());
        return new ArrayList<>(distinct);
    }

    /**
     * ACME clients agree to terms only when the directory advertises them, so a profile that requires agreement without
     * a terms URL would require nothing; checked on the merged profile so create and partial edit are held to the same
     * rule.
     */
    private static void requireTermsUrlWhenAgreementIsRequired(AcmeProfile acmeProfile) {
        boolean required = Boolean.TRUE.equals(acmeProfile.isRequireTermsOfService());
        boolean hasUrl = acmeProfile.getTermsOfServiceUrl() != null && !acmeProfile.getTermsOfServiceUrl().isBlank();
        if (required && !hasUrl) {
            throw new ValidationException(
                    ValidationError.create("Requiring agreement to the Terms of Service needs a Terms of Service URL"));
        }
    }

    private AcmeProfileDto mapToDetailDto(AcmeProfile acmeProfile) {
        AcmeProfileDto dto = acmeProfile.mapToDto();
        dto
                .setCustomAttributes(
                        attributeEngine.getObjectCustomAttributesContent(Resource.ACME_PROFILE, acmeProfile.getUuid()));
        if (acmeProfile.getRaProfile() != null) {
            dto
                    .setIssueCertificateAttributes(attributeEngine
                            .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(acmeProfile
                                            .getRaProfile()
                                            .getAuthorityInstanceReference()
                                            .getConnectorUuid())
                                    .operation(AttributeOperation.CERTIFICATE_ISSUE)
                                    .build()));
            dto
                    .setRevokeCertificateAttributes(attributeEngine
                            .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(acmeProfile
                                            .getRaProfile()
                                            .getAuthorityInstanceReference()
                                            .getConnectorUuid())
                                    .operation(AttributeOperation.CERTIFICATE_REVOKE)
                                    .build()));
        }
        if (acmeProfile.getCertificateAssociations() != null) {
            dto
                    .setCertificateAssociations(acmeProfile
                            .getCertificateAssociations()
                            .mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine
                                    .loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }
        return dto;
    }

    private AcmeProfileDto updateAndMapDtoAttributes(AcmeProfile acmeProfile, RaProfile raProfile,
            List<RequestAttribute> issueCertificateAttributes, List<RequestAttribute> revokeCertificateAttributes,
            List<RequestAttribute> customAttributes) throws NotFoundException, AttributeException {
        AcmeProfileDto dto = acmeProfile.mapToDto();
        dto
                .setCustomAttributes(attributeEngine
                        .updateObjectCustomAttributesContent(Resource.ACME_PROFILE, acmeProfile.getUuid(),
                                customAttributes));
        if (raProfile != null) {
            dto
                    .setIssueCertificateAttributes(attributeEngine
                            .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid())
                                    .operation(AttributeOperation.CERTIFICATE_ISSUE)
                                    .build(), issueCertificateAttributes));
            dto
                    .setRevokeCertificateAttributes(attributeEngine
                            .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                                    .builder(Resource.ACME_PROFILE, acmeProfile.getUuid())
                                    .connector(raProfile.getAuthorityInstanceReference().getConnectorUuid())
                                    .operation(AttributeOperation.CERTIFICATE_REVOKE)
                                    .build(), revokeCertificateAttributes));
        }

        if (acmeProfile.getCertificateAssociations() != null) {
            dto
                    .setCertificateAssociations(acmeProfile
                            .getCertificateAssociations()
                            .mapToDto((attributeType, connectorUuid, requestAttributes) -> attributeEngine
                                    .loadResponseAttributes(attributeType, connectorUuid, requestAttributes)));
        }

        return dto;
    }

    private static ProtocolCertificateAssociations getCertificateAssociation(AcmeProfileEditRequestDto request,
            AcmeProfile acmeProfile) {
        ProtocolCertificateAssociations certificateAssociation = acmeProfile.getCertificateAssociations();
        if (certificateAssociation == null) {
            certificateAssociation = new ProtocolCertificateAssociations();
        }
        certificateAssociation.setOwnerUuid(request.getCertificateAssociations().getOwnerUuid());
        certificateAssociation.setGroupUuids(request.getCertificateAssociations().getGroupUuids());
        certificateAssociation.setCustomAttributes(request.getCertificateAssociations().getCustomAttributes());
        return certificateAssociation;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public void deleteAcmeProfile(SecuredUUID uuid) throws NotFoundException, ValidationException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        deleteAcmeProfile(acmeProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void enableAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        if (acmeProfile.isEnabled() != null && acmeProfile.isEnabled()) {
            throw new ValidationException("ACME Profile is already enabled");
        }
        acmeProfile.setEnabled(true);
        acmeProfileRepository.save(acmeProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void disableAcmeProfile(SecuredUUID uuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        if (!acmeProfile.isEnabled()) {
            throw new ValidationException("ACME Profile is already disabled");
        }
        acmeProfile.setEnabled(false);
        acmeProfileRepository.save(acmeProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableAcmeProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
                if (acmeProfile.isEnabled()) {
                    logger.warn("ACME Profile is already enabled");
                }
                acmeProfile.setEnabled(true);
                acmeProfileRepository.save(acmeProfile);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableAcmeProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids) {
            try {
                AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
                if (acmeProfile.isEnabled() != null && acmeProfile.isEnabled()) {
                    logger.warn("ACME Profile is already disabled");
                }
                acmeProfile.setEnabled(false);
                acmeProfileRepository.save(acmeProfile);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteAcmeProfile(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AcmeProfile acmeProfile = null;
            try {
                acmeProfile = getAcmeProfileEntity(uuid);
                deleteAcmeProfile(acmeProfile);
            } catch (Exception e) {
                logger.error(e.getMessage());
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(), acmeProfile != null ? acmeProfile.getName() : "", e,
                                        "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public void updateRaProfile(SecuredUUID uuid, String raProfileUuid) throws NotFoundException {
        AcmeProfile acmeProfile = getAcmeProfileEntity(uuid);
        RaProfile newRaProfile = getRaProfile(raProfileUuid);
        acmeProfile.setRaProfile(newRaProfile);
        acmeProfileRepository.save(acmeProfile);
        acmeAccountRepository.updateRaProfileForDefaultAccounts(acmeProfile.getUuid(), newRaProfile.getUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkForceRemoveACMEProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AcmeProfile acmeProfile = null;
            try {
                acmeProfile = getAcmeProfileEntity(uuid);
                SecuredList<RaProfile> raProfiles = raProfileService
                        .listRaProfilesAssociatedWithAcmeProfile(acmeProfile.getUuid().toString(),
                                SecurityFilter.create());
                // acme profile only from allowed ones, but that would make the forbidden ra profiles point to
                // nonexistent acme profile.
                raProfileService
                        .bulkRemoveAssociatedAcmeProfile(raProfiles
                                .getAll()
                                .stream()
                                .map(UniquelyIdentifiedAndAudited::getSecuredUuid)
                                .collect(Collectors.toList()));
                deleteAcmeProfile(acmeProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(), acmeProfile != null ? acmeProfile.getName() : "", e,
                                        "Delete failed"));
            }
        }
        return messages;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return acmeProfileRepository.findResourceObject(objectUuid, AcmeProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return acmeProfileRepository.findResourceObject(objectUuid.getValue(), AcmeProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return acmeProfileRepository.listResourceObjects(filter, AcmeProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getAcmeProfileEntity(uuid);
        // Since there are is no parent to the ACME Profile, exclusive parent permission evaluation need not be done
    }

    private RaProfile getRaProfile(String uuid) throws NotFoundException {
        return raProfileService.getRaProfileEntity(SecuredUUID.fromString(uuid));
    }

    private AcmeProfile getAcmeProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return acmeProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(AcmeProfile.class, uuid));
    }

    private void deleteAcmeProfile(AcmeProfile acmeProfile) {
        SecuredList<RaProfile> raProfiles = raProfileService
                .listRaProfilesAssociatedWithAcmeProfile(acmeProfile.getUuid().toString(), SecurityFilter.create());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create(String
                            .format("Dependent RA Profiles (%d): %s", raProfiles.size(),
                                    raProfiles
                                            .getAllowed()
                                            .stream()
                                            .map(RaProfile::getName)
                                            .collect(Collectors.joining(",")))));
        } else {
            attributeEngine.deleteObjectAttributeContent(Resource.ACME_PROFILE, acmeProfile.getUuid());
            commentService.removeObjectComments(Resource.ACME_PROFILE, acmeProfile.getUuid());
            acmeProfileRepository.delete(acmeProfile);
        }
    }
}
