package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.est.BaseEstProfileRequestDto;
import com.otilm.api.model.client.est.EstProfileEditRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.entity.est.EstProfile_;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.mapper.est.EstProfileMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.service.EstProfileInternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.service.est.EstKeyRecoveryKeyAttributes;
import com.otilm.core.service.est.EstProfileReferenceResolver;
import com.otilm.core.service.est.EstProfileReferenceResolver.References;
import com.otilm.core.service.writer.est.EstProfileWriter;
import com.otilm.core.util.CertificateUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.service.est.EstProfileReferenceResolver.issueConnectorUuid;

@Slf4j
@Service(Resource.Codes.EST_PROFILE)
public class EstProfileServiceImpl implements EstProfileExternalService, EstProfileInternalService {

    private static final String SYSTEM_DEFAULT_INDEX = "uk_est_profile_single_system_default";
    private static final String SYSTEM_DEFAULT_CLASH = "Another EST Profile became the system default at the same time; repeat the request";
    private static final String CREDENTIALS_CHANGED = "The basic credentials of the EST Profile changed at the same time; repeat the request";
    private static final String ISSUE_ATTRIBUTES_OF_THE_CURRENT_CONNECTOR = "The issue certificate attributes of the EST Profile are for the connector of its current RA Profile; update the EST Profile with issue certificate attributes for the new RA Profile instead";
    private static final ObjectMapper KEY_ATTRIBUTES_JSON = ObjectMapperFactory.storage();

    private EstProfileRepository estProfileRepository;
    private EstProfileWriter estProfileWriter;
    private EstProfileReferenceResolver referenceResolver;
    private RaProfileRepository raProfileRepository;
    private RaProfileInternalService raProfileService;
    private SecretRepository secretRepository;
    private CertificateRepository certificateRepository;
    private AttributeEngine attributeEngine;
    private ProtocolCertificateAssociationsRepository certificateAssociationRepository;
    private CommentInternalService commentService;
    private TransactionTemplate transactionTemplate;
    private EstProfileServiceImpl self;

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<EstProfileDto> listEstProfiles(SecurityFilter filter, String origin) {
        return estProfileRepository
                .findUsingSecurityFilter(filter)
                .stream()
                .map(profile -> EstProfileMapper.toDto(profile, origin))
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public EstProfileDetailDto getEstProfile(SecuredUUID uuid, String origin) throws NotFoundException {
        EstProfile profile = findProfile(uuid);
        List<ResponseAttribute> customAttributes = attributeEngine
                .getObjectCustomAttributesContent(Resource.EST_PROFILE, profile.getUuid());
        return toDetailDto(profile, customAttributes, readIssueAttributes(profile), origin);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.CREATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public EstProfileDetailDto createEstProfile(EstProfileRequestDto request, String origin)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        requireNameIsFree(request.getName());
        References references = referenceResolver.resolve(request, List.of());
        SecurityResourceFilter customAttributesFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();
        return writeInTransaction(() -> insert(request, references, customAttributesFilter, origin));
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public EstProfileDetailDto updateEstProfile(SecuredUUID uuid, EstProfileEditRequestDto request, String origin)
            throws ConnectorException, AttributeException, NotFoundException {
        requireProfileExists(uuid);
        List<UUID> acceptedSecretUuids = estProfileRepository.findBasicCredentialSecretUuids(uuid.getValue());
        References references = referenceResolver.resolve(request, acceptedSecretUuids);
        SecurityResourceFilter customAttributesFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();
        return writeInTransaction(() -> update(uuid, request, references, customAttributesFilter, origin));
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.DELETE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void deleteEstProfile(SecuredUUID uuid) throws NotFoundException {
        self.deleteInOwnTransaction(uuid, false, raProfilesTheCallerMayList(uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteEstProfiles(List<SecuredUUID> uuids) {
        return deleteEach(uuids, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> forceDeleteEstProfiles(List<SecuredUUID> uuids) {
        return deleteEach(uuids, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.ENABLE)
    @Transactional(rollbackFor = Exception.class)
    public void enableEstProfile(SecuredUUID uuid) throws NotFoundException {
        setEnabled(uuid, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.ENABLE)
    @Transactional(rollbackFor = Exception.class)
    public void disableEstProfile(SecuredUUID uuid) throws NotFoundException {
        setEnabled(uuid, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.ENABLE)
    public void bulkEnableEstProfiles(List<SecuredUUID> uuids) {
        setEnabledEach(uuids, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.ENABLE)
    public void bulkDisableEstProfiles(List<SecuredUUID> uuids) {
        setEnabledEach(uuids, false);
    }

    /**
     * The issue attributes stored for the profile stay as they are, so while there are any, the RA Profile can change
     * only to one of the same connector. The RA Profile's read is authorized outside any transaction, and only then is
     * the profile locked and changed in a transaction of its own.
     */
    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void updateRaProfile(SecuredUUID uuid, UUID raProfileUuid) throws NotFoundException {
        RaProfile raProfile = referenceResolver.resolveRaProfile(raProfileUuid);
        self.setRaProfileInOwnTransaction(uuid, raProfile);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ResourceExtensionService
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return estProfileRepository.findResourceObject(objectUuid, EstProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return estProfileRepository.findResourceObject(objectUuid.getValue(), EstProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return estProfileRepository.listResourceObjects(filter, EstProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.EST_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(readOnly = true)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        findProfile(uuid);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Lookups and checks
    // ──────────────────────────────────────────────────────────────────────────

    private EstProfile findProfile(SecuredUUID uuid) throws NotFoundException {
        return estProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(EstProfile.class, uuid));
    }

    private EstProfile lockedProfile(SecuredUUID uuid) throws NotFoundException {
        return estProfileRepository
                .findWithLockByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(EstProfile.class, uuid));
    }

    /**
     * Checks without loading the profile: a copy loaded here could stay in the request's persistence context and be the
     * one the write transaction finds, older than the row by the time the connector has answered.
     */
    private void requireProfileExists(SecuredUUID uuid) throws NotFoundException {
        if (!estProfileRepository.existsById(uuid.getValue())) {
            throw new NotFoundException(EstProfile.class, uuid);
        }
    }

    /** EST Profile names and the names of RA Profiles with EST activated share one namespace of EST labels. */
    private void requireNameIsFree(String name) throws AlreadyExistException {
        if (estProfileRepository.findByName(name).isPresent()) {
            throw new AlreadyExistException("EST Profile with name '" + name + "' already exists.");
        }
        requireNoRaProfileLabelled(name);
    }

    /**
     * Asked of the row as committed rather than of an RA Profile, so no copy the request's persistence context still
     * holds from before the connector call can answer for it.
     */
    private void requireNoRaProfileLabelled(String name) {
        if (raProfileRepository.existsByNameAndEstProfileUuidIsNotNull(name)) {
            throw new ValidationException("Name is already the EST label of RA Profile " + name);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete and enable, under the profile's row lock
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * The name for a failure message is read first, as a projection that leaves no copy of the profile in the
     * persistence context, so the failure branch makes no database call that could itself fail.
     */
    private List<BulkActionMessageDto> deleteEach(List<SecuredUUID> uuids, boolean force) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            String name = "";
            try {
                name = estProfileRepository.findResourceObject(uuid.getValue(), EstProfile_.name).getName();
                Set<UUID> namedRaProfileUuids = force ? Set.of() : raProfilesTheCallerMayList(uuid);
                self.deleteInOwnTransaction(uuid, force, namedRaProfileUuids);
            } catch (Exception e) {
                logBulkFailure("delete", uuid, e);
                messages.add(BulkActionMessageDto.failure(uuid.toString(), name, e, "Delete failed"));
            }
        }
        return messages;
    }

    /**
     * The RA Profiles with the profile activated that the caller may list, the only ones a refused delete names. Asked
     * for before the profile is locked, so the authorization service is never waited for while the lock is held, and
     * only when there are any, so deleting a profile no RA Profile has activated takes no RA Profile permission. A
     * caller who may not list RA Profiles is named none.
     */
    private Set<UUID> raProfilesTheCallerMayList(SecuredUUID uuid) {
        if (!raProfileRepository.existsByEstProfileUuid(uuid.getValue())) {
            return Set.of();
        }
        try {
            return raProfileService
                    .listRaProfilesAssociatedWithEstProfile(uuid.getValue(), SecurityFilter.create())
                    .getAllowed()
                    .stream()
                    .map(RaProfile::getUuid)
                    .collect(Collectors.toSet());
        } catch (AccessDeniedException e) {
            log.debug("RA Profiles with EST Profile {} are not named: the caller may not list RA Profiles", uuid);
            return Set.of();
        }
    }

    /**
     * @param namedRaProfileUuids the RA Profiles a refusal may name: those the caller may list, none for a force
     * delete, which leaves none to refuse for
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(SecuredUUID uuid, boolean force, Set<UUID> namedRaProfileUuids)
            throws NotFoundException {
        EstProfile profile = lockedProfile(uuid);
        if (force) {
            deactivateOnRaProfiles(profile);
        }
        delete(profile, namedRaProfileUuids);
    }

    /**
     * An RA Profile with EST activated serves its label with the profile, so the profile stays while one does. Every
     * such RA Profile is counted, and only the given ones are named.
     */
    private void delete(EstProfile profile, Set<UUID> namedRaProfileUuids) {
        List<RaProfile> raProfiles = raProfileRepository.findAllByEstProfileUuid(profile.getUuid());
        if (!raProfiles.isEmpty()) {
            throw new ValidationException(associatedRaProfilesRefusal(raProfiles, namedRaProfileUuids));
        }
        attributeEngine.deleteObjectAttributeContent(Resource.EST_PROFILE, profile.getUuid());
        commentService.removeObjectComments(Resource.EST_PROFILE, profile.getUuid());
        estProfileRepository.delete(profile);
    }

    private static String associatedRaProfilesRefusal(List<RaProfile> raProfiles, Set<UUID> namedRaProfileUuids) {
        String refusal = "Cannot remove as there are associated RA Profiles (%d)".formatted(raProfiles.size());
        List<String> names = raProfiles
                .stream()
                .filter(raProfile -> namedRaProfileUuids.contains(raProfile.getUuid()))
                .map(RaProfile::getName)
                .toList();
        return names.isEmpty() ? refusal : refusal + ": " + String.join(", ", names);
    }

    /**
     * Every RA Profile, including those the caller may not see: none may be left pointing at a deleted profile. They
     * are read under their row locks, so one activated with another EST Profile meanwhile keeps that activation.
     */
    private void deactivateOnRaProfiles(EstProfile profile) {
        for (RaProfile raProfile : raProfileRepository.findWithLockByEstProfileUuid(profile.getUuid())) {
            raProfile.setEstProfile(null);
            raProfile.getProtocolAttribute().setEstIssueCertificateAttributes(null);
            raProfileRepository.save(raProfile);
        }
    }

    private void setEnabledEach(List<SecuredUUID> uuids, boolean enabled) {
        for (SecuredUUID uuid : uuids) {
            try {
                self.setEnabledInOwnTransaction(uuid, enabled);
            } catch (Exception e) {
                logBulkFailure(enabled ? "enable" : "disable", uuid, e);
            }
        }
    }

    /**
     * A refusal the platform shaped, such as the RA Profile guard or an unknown profile, is expected in a bulk request:
     * its message names the reason and carries no secret. Anything else is unexpected and keeps its trace.
     */
    static void logBulkFailure(String operation, SecuredUUID uuid, Exception e) {
        if (e instanceof PlatformException) {
            log.warn("Could not {} EST Profile {}: {}", operation, uuid, e.getMessage());
        } else {
            log.error("Failed to {} EST Profile {}", operation, uuid, e);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void setEnabledInOwnTransaction(SecuredUUID uuid, boolean enabled) throws NotFoundException {
        setEnabled(uuid, enabled);
    }

    private void setEnabled(SecuredUUID uuid, boolean enabled) throws NotFoundException {
        EstProfile profile = lockedProfile(uuid);
        profile.setEnabled(enabled);
        estProfileRepository.save(profile);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void setRaProfileInOwnTransaction(SecuredUUID uuid, RaProfile raProfile) throws NotFoundException {
        EstProfile profile = lockedProfile(uuid);
        requireIssueAttributesStillApply(profile, raProfile);
        profile.setRaProfile(raProfile);
        estProfileRepository.save(profile);
    }

    /**
     * Issue attributes are stored keyed by the connector of the default RA Profile, so a default of another connector,
     * or none, would leave them behind: no longer applied, not deleted by a later update, and applied again if the
     * profile came back to the connector.
     */
    private void requireIssueAttributesStillApply(EstProfile profile, RaProfile raProfile) {
        boolean sameConnector = Objects
                .equals(issueConnectorUuid(profile.getRaProfile()), issueConnectorUuid(raProfile));
        if (!sameConnector && !readIssueAttributes(profile).isEmpty()) {
            throw new ValidationException(ISSUE_ATTRIBUTES_OF_THE_CURRENT_CONNECTOR);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Writes, all in one transaction
    // ──────────────────────────────────────────────────────────────────────────

    private EstProfileDetailDto writeInTransaction(ProfileWrite write) throws NotFoundException, AttributeException {
        try {
            return transactionTemplate.execute(status -> {
                try {
                    return write.run();
                } catch (NotFoundException | AttributeException e) {
                    throw new CheckedWriteFailure(e);
                }
            });
        } catch (CheckedWriteFailure failure) {
            if (failure.getCause() instanceof NotFoundException notFound) {
                throw notFound;
            }
            throw (AttributeException) failure.getCause();
        } catch (DataIntegrityViolationException e) {
            if (isSystemDefaultClash(e)) {
                throw new ValidationException(SYSTEM_DEFAULT_CLASH);
            }
            throw e;
        }
    }

    /** Whether the save lost a race with another profile becoming the system default. */
    static boolean isSystemDefaultClash(DataIntegrityViolationException e) {
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException constraintViolation) {
                return SYSTEM_DEFAULT_INDEX.equalsIgnoreCase(constraintViolation.getConstraintName());
            }
        }
        return false;
    }

    /**
     * The label is checked again before anything is written: EST may have been activated on an RA Profile of that name
     * while the connector was answering.
     */
    private EstProfileDetailDto insert(EstProfileRequestDto request, References references,
            SecurityResourceFilter customAttributesFilter, String origin) throws NotFoundException, AttributeException {
        requireNoRaProfileLabelled(request.getName());
        if (request.isSystemDefault()) {
            estProfileWriter.clearSystemDefault();
        }
        EstProfile profile = new EstProfile();
        profile.setName(request.getName());
        return save(profile, null, request, references, customAttributesFilter, origin);
    }

    /**
     * Reads the profile in this transaction under a row lock, so a change committed meanwhile is not overwritten by the
     * whole-row write and its lazy certificate associations can be changed. It is changed only after the previous
     * default is cleared, so no pending change to it can reach the database before the clearing update and trip the
     * single-default index.
     */
    private EstProfileDetailDto update(SecuredUUID uuid, EstProfileEditRequestDto request, References references,
            SecurityResourceFilter customAttributesFilter, String origin) throws NotFoundException, AttributeException {
        EstProfile profile = lockedProfile(uuid);
        requireKeptSecretsStillAccepted(profile, references);
        UUID previousConnectorUuid = issueConnectorUuid(profile.getRaProfile());
        if (request.isSystemDefault()) {
            estProfileWriter.clearSystemDefaultExcept(profile.getUuid());
        }
        return save(profile, previousConnectorUuid, request, references, customAttributesFilter, origin);
    }

    /**
     * The kept secrets passed without the content gate because the profile accepted them when the update began; one
     * that an update committed since has dropped would otherwise come back unchecked.
     */
    private static void requireKeptSecretsStillAccepted(EstProfile profile, References references) {
        if (!profile.getBasicCredentialSecretUuids().containsAll(references.keptSecretUuids())) {
            throw new ValidationException(CREDENTIALS_CHANGED);
        }
    }

    /**
     * @param customAttributesFilter the caller's custom attribute permissions, asked for before the transaction began,
     * so the authorization service is never waited for while the transaction holds the profile
     */
    private EstProfileDetailDto save(EstProfile profile, UUID previousConnectorUuid, BaseEstProfileRequestDto request,
            References references, SecurityResourceFilter customAttributesFilter, String origin)
            throws NotFoundException, AttributeException {
        if (references.keyRecoveryTokenProfile() != null) {
            estProfileWriter.requireKeyRecoveryTokenProfileEnabled(references.keyRecoveryTokenProfile().getUuid());
        }
        applySettings(profile, request, references);
        profile
                .setCertificateAssociations(saveCertificateAssociations(profile.getCertificateAssociations(),
                        request.getCertificateAssociations()));
        EstProfile saved = estProfileRepository.saveAndFlush(profile);
        List<ResponseAttribute> customAttributes = attributeEngine
                .updateObjectCustomAttributesContent(Resource.EST_PROFILE, saved.getUuid(),
                        request.getCustomAttributes(), customAttributesFilter);
        List<ResponseAttribute> issueAttributes = replaceIssueAttributes(saved.getUuid(), previousConnectorUuid,
                issueConnectorUuid(references.raProfile()), request.getIssueCertificateAttributes());
        return toDetailDto(saved, customAttributes, issueAttributes, origin);
    }

    private static void applySettings(EstProfile profile, BaseEstProfileRequestDto request, References references) {
        profile.setDescription(request.getDescription());
        profile.setRaProfile(references.raProfile());
        profile.setSystemDefault(request.isSystemDefault());
        profile.setAuthenticationPolicy(request.getAuthenticationPolicy());
        profile.setBasicCredentialSecretUuids(references.basicCredentialSecretUuids());
        profile.setTrustedCaCertificateUuids(references.trustedCaCertificateUuids());
        profile.setAllowRenewal(request.isAllowRenewal());
        profile.setAllowRekey(request.isAllowRekey());
        profile.setRenewalThreshold(request.getRenewalThreshold());
        profile.setServerKeyGeneration(request.isServerKeyGeneration());
        profile.setIssueWaitTimeout(request.getIssueWaitTimeout());
        profile.setRetryAfter(request.getRetryAfter());
        profile.setServerKeyGenerationTimeout(request.getServerKeyGenerationTimeout());
        profile.setKeyRecovery(request.isKeyRecovery());
        profile.setKeyRecoveryTokenProfile(references.keyRecoveryTokenProfile());
        profile.setKeyRecoveryKeyAttributes(toJson(request.getKeyRecoveryKeyAttributes()));
    }

    private ProtocolCertificateAssociations saveCertificateAssociations(ProtocolCertificateAssociations current,
            ProtocolCertificateAssociationsRequestDto request) {
        if (request == null || request.isEmpty()) {
            return null;
        }
        ProtocolCertificateAssociations associations = current != null
                ? current
                : new ProtocolCertificateAssociations();
        associations.setOwnerUuid(request.getOwnerUuid());
        associations.setGroupUuids(request.getGroupUuids());
        associations.setCustomAttributes(request.getCustomAttributes());
        return certificateAssociationRepository.save(associations);
    }

    private List<ResponseAttribute> replaceIssueAttributes(UUID profileUuid, UUID previousConnectorUuid,
            UUID connectorUuid, List<RequestAttribute> issueAttributes) throws AttributeException {
        if (previousConnectorUuid != null) {
            attributeEngine
                    .deleteOperationObjectAttributesContent(AttributeType.DATA,
                            issueAttributesInfo(profileUuid, previousConnectorUuid));
        }
        if (connectorUuid == null) {
            return List.of();
        }
        return attributeEngine
                .updateObjectDataAttributesContent(issueAttributesInfo(profileUuid, connectorUuid), issueAttributes);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Mapping
    // ──────────────────────────────────────────────────────────────────────────

    private EstProfileDetailDto toDetailDto(EstProfile profile, List<ResponseAttribute> customAttributes,
            List<ResponseAttribute> issueAttributes, String origin) {
        EstProfileDetailDto dto = EstProfileMapper.toDetailDto(profile, origin);
        dto
                .setBasicCredentialSecrets(namesInStoredOrder(profile.getBasicCredentialSecretUuids(),
                        secretRepository::findByUuidIn, Secret::getName));
        dto
                .setTrustedCaCertificates(
                        namesInStoredOrder(profile.getTrustedCaCertificateUuids(), certificateRepository::findAllById,
                                certificate -> CertificateUtil.formatCommonName(certificate.getCommonName())));
        TokenProfile tokenProfile = profile.getKeyRecoveryTokenProfile();
        if (tokenProfile != null) {
            dto.setKeyRecoveryTokenProfile(new NameAndUuidDto(tokenProfile.getUuid(), tokenProfile.getName()));
        }
        dto.setKeyRecoveryKeyAttributes(keyAttributesOf(profile));
        dto.setIssueCertificateAttributes(issueAttributes);
        dto.setCustomAttributes(customAttributes);
        ProtocolCertificateAssociations associations = profile.getCertificateAssociations();
        if (associations != null) {
            dto.setCertificateAssociations(associations.mapToDto(attributeEngine::loadResponseAttributes));
        }
        return dto;
    }

    private List<ResponseAttribute> readIssueAttributes(EstProfile profile) {
        UUID connectorUuid = issueConnectorUuid(profile.getRaProfile());
        if (connectorUuid == null) {
            return List.of();
        }
        return attributeEngine.getObjectDataAttributesContent(issueAttributesInfo(profile.getUuid(), connectorUuid));
    }

    private static ObjectAttributeContentInfo issueAttributesInfo(UUID profileUuid, UUID connectorUuid) {
        return ObjectAttributeContentInfo
                .builder(Resource.EST_PROFILE, profileUuid)
                .connector(connectorUuid)
                .operation(AttributeOperation.CERTIFICATE_ISSUE)
                .build();
    }

    /** Names the referenced objects in the order the profile lists them, leaving out any that no longer exists. */
    private static <T extends UniquelyIdentifiedAndAudited> List<NameAndUuidDto> namesInStoredOrder(List<UUID> uuids,
            Function<List<UUID>, List<T>> load, Function<T, String> nameOf) {
        if (uuids.isEmpty()) {
            return List.of();
        }
        Map<UUID, String> names = load
                .apply(uuids)
                .stream()
                .collect(Collectors.toMap(UniquelyIdentifiedAndAudited::getUuid, nameOf));
        return uuids
                .stream()
                .filter(names::containsKey)
                .map(uuid -> new NameAndUuidDto(uuid, names.get(uuid)))
                .toList();
    }

    private static String toJson(List<RequestAttribute> keyAttributes) {
        if (keyAttributes == null || keyAttributes.isEmpty()) {
            return null;
        }
        try {
            return KEY_ATTRIBUTES_JSON.writeValueAsString(keyAttributes);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Key recovery key attributes cannot be written as JSON", e);
        }
    }

    private static List<ResponseAttribute> keyAttributesOf(EstProfile profile) {
        return AttributeEngine.getResponseAttributesFromRequestAttributes(EstKeyRecoveryKeyAttributes.of(profile));
    }

    @FunctionalInterface
    private interface ProfileWrite {
        EstProfileDetailDto run() throws NotFoundException, AttributeException;
    }

    /** Carries a checked failure out of the transaction callback, rolling the transaction back on the way. */
    private static final class CheckedWriteFailure extends RuntimeException implements PlatformException {
        private CheckedWriteFailure(Exception cause) {
            super(cause);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Injection
    // ──────────────────────────────────────────────────────────────────────────

    @Autowired
    public void setEstProfileRepository(EstProfileRepository estProfileRepository) {
        this.estProfileRepository = estProfileRepository;
    }

    @Autowired
    public void setEstProfileWriter(EstProfileWriter estProfileWriter) {
        this.estProfileWriter = estProfileWriter;
    }

    @Autowired
    public void setReferenceResolver(EstProfileReferenceResolver referenceResolver) {
        this.referenceResolver = referenceResolver;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setRaProfileService(RaProfileInternalService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCertificateAssociationRepository(
            ProtocolCertificateAssociationsRepository certificateAssociationRepository) {
        this.certificateAssociationRepository = certificateAssociationRepository;
    }

    @Autowired
    public void setCommentService(CommentInternalService commentService) {
        this.commentService = commentService;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Lazy
    @Autowired
    public void setSelf(EstProfileServiceImpl self) {
        this.self = self;
    }
}
