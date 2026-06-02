package com.czertainly.core.service.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.czertainly.api.model.client.signing.profile.workflow.*;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileListDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.DelegatedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.ManagedSigningRequestSchemeInterface;
import com.czertainly.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.czertainly.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.scheme.SigningSchemeRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.StaticKeyManagedSigningRequestDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.config.cache.CacheEvictor;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Audited_;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfile_;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.service.writer.SigningProfileWriter;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.mapper.signing.SigningProfileMapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CryptographicOperationService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.SigningProfileService;
import com.czertainly.core.service.TokenProfileService;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service(Resource.Codes.SIGNING_PROFILE)
@Slf4j
public class SigningProfileServiceImpl implements SigningProfileService {

    /**
     * Defines which signing protocols are allowed for each workflow type.
     */
    private static final Map<SigningWorkflowType, Set<SigningProtocol>> SUPPORTED_PROTOCOLS = Map.of(
            SigningWorkflowType.TIMESTAMPING, EnumSet.of(SigningProtocol.TSP)
    );

    private SigningProfileServiceImpl self;
    private CryptographicOperationService cryptographicOperationService;
    private CertificateService certificateService;
    private ConnectorService connectorService;
    private TokenProfileService tokenProfileService;
    private RaProfileService raProfileService;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private SigningProfileRepository signingProfileRepository;
    private SigningProfileVersionRepository signingProfileVersionRepository;
    private SigningProfileWriter signingProfileWriter;
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private TspProfileService tspProfileService;
    private AttributeEngine attributeEngine;
    private ConnectorApiFactory connectorApiFactory;
    private CacheEvictor cacheEvictor;

    // ──────────────────────────────────────────────────────────────────────────
    // List / search
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.SIGNING_PROFILE, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_NAME),
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_ENABLED),
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_SIGNING_SCHEME),
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_WORKFLOW_TYPE),
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_TSP_PROFILE, tspProfileService.findAllNames()),
                SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION, timeQualityConfigurationRepository.findAllNames())
        ));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    public List<SigningProtocol> listSupportedProtocols(SigningWorkflowType workflowType) {
        return List.copyOf(SUPPORTED_PROTOCOLS.getOrDefault(workflowType, EnumSet.noneOf(SigningProtocol.class)));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningProfileListDto> listSigningProfiles(SearchRequestDto request, SecurityFilter filter) {
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<SigningProfile>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<SigningProfileListDto> profiles = signingProfileRepository.findUsingSecurityFilter(filter, List.of(), predicate, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream()
                .map(SigningProfileMapper::toListDto)
                .toList();
        PaginationResponseDto<SigningProfileListDto> response = new PaginationResponseDto<>();
        response.setItems(profiles);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        response.setTotalItems(signingProfileRepository.countUsingSecurityFilter(filter, predicate));
        response.setTotalPages((int) Math.ceil((double) response.getTotalItems() / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SimplifiedSigningProfileDto> listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter) {
        return listSigningProfileEntitiesAssociatedTimeQualityConfiguration(timeQualityConfigurationUuid, filter)
                .getAllowed()
                .stream()
                .map(SigningProfileMapper::toSimpleDto)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public SecuredList<SigningProfile> listSigningProfileEntitiesAssociatedTimeQualityConfiguration(SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter) {
        List<SigningProfile> signingProfiles = signingProfileRepository.findAllByTimeQualityConfigurationUuid(timeQualityConfigurationUuid.getValue());
        return SecuredList.fromFilter(filter, signingProfiles);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public SecuredList<SigningProfile> listSigningProfilesAssociatedWithTsp(SecuredUUID tspProfileUuid, SecurityFilter filter) {
        List<SigningProfile> signingProfiles = signingProfileRepository.findAllByTspProfileUuid(tspProfileUuid.getValue());
        return SecuredList.fromFilter(filter, signingProfiles);
    }

    @Override
    public List<CertificateDto> listSigningCertificates(SigningWorkflowType signingWorkflowType, boolean qualifiedTimestamp) {
        return certificateService.listDigitalSigningCertificates(SecurityFilter.create(), signingWorkflowType, qualifiedTimestamp);
    }

    @Override
    @Transactional(readOnly = true)
    public List<BaseAttribute> listSignatureAttributesForCertificate(UUID certificateUuid) throws NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromUUID(certificateUuid));
        if (certificate.getKey() == null) {
            return List.of();
        }
        return cryptographicKeyItemRepository.findByKeyUuidIn(List.of(certificate.getKey().getUuid()))
                .stream()
                .findFirst()
                .map(item -> cryptographicOperationService.listSignatureAttributes(item.getKeyAlgorithm()))
                .orElse(List.of());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ANY)
    @Transactional(readOnly = true)
    public List<BaseAttribute> listSignatureFormatterConnectorAttributes(UUID connectorUuid, SecuredUUID signingProfileUuid) throws NotFoundException, ConnectorException, AttributeException {
        return fetchFormatterAttributeDefinitions(connectorUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<String> findAllNames() {
        return signingProfileRepository.findAllNames();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get (with optional version)
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningProfile getSigningProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return findByUuid(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    public SigningProfileModel<?, ?> getSigningProfileModel(String name) throws NotFoundException {
        return self.loadSigningProfileModel(name);
    }

    // Package-private internal cache loader, self-invoked.
    @Cacheable(value = CacheConfig.SIGNING_PROFILE_CACHE, key = "#name", sync = true)
    @Transactional(readOnly = true)
    SigningProfileModel<?, ?> loadSigningProfileModel(String name) throws NotFoundException {
        SigningProfile profile = signingProfileRepository.findByName(name)
                .orElseThrow(() -> new NotFoundException(SigningProfile.class, name));
        SigningProfileVersion currentVersion = profile.getVersions().stream()
                .filter(v -> v.getVersion() == profile.getLatestVersion())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Signing Profile '" + name
                        + "' has no row for latestVersion " + profile.getLatestVersion()));

        List<RequestAttribute> signingOperationAttributes = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .operation(AttributeOperation.SIGN)
                        .version(currentVersion.getVersion()).build());
        List<RequestAttribute> signatureFormatterConnectorAttributes = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .connector(currentVersion.getSignatureFormatterConnectorUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER)
                        .version(currentVersion.getVersion()).build());

        // Narrow scope: only managed-timestamping profiles are cacheable for now.
        return SigningProfileMapper.toManagedTimestampingModel(
                profile, currentVersion, signingOperationAttributes, signatureFormatterConnectorAttributes);
    }

    /**
     * Evicts a signing profile by name. Callers inside a {@code @Transactional} method
     * (persistUpdate/delete/enable/disable/activateTsp/deactivateTsp) reach the deferred branch, so the cache entry
     * survives until the mutating transaction commits. Callers whose transaction has already committed (the
     * {@code NOT_SUPPORTED} create path) evict immediately.
     */
    private void evictSigningProfileCache(String name) {
        cacheEvictor.evict(CacheConfig.SIGNING_PROFILE_CACHE, name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningProfileDto getSigningProfile(SecuredUUID uuid, Integer version) throws NotFoundException {
        SigningProfile profile = findByUuid(uuid);
        if (version != null) {
            SigningProfileVersion spv = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(profile.getUuid(), version)
                    .orElseThrow(() -> new NotFoundException("Signing Profile version " + version + " not found"));
            return buildDtoFromVersion(profile, spv);
        } else {
            return buildDtoFromProfile(profile);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.CREATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public SigningProfileDto createSigningProfile(SigningProfileRequestDto request)
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        if (signingProfileRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException("Signing Profile with name '" + request.getName() + "' already exists.");
        }
        validateSigningSchemeCoherence(request.getSigningScheme());
        attributeEngine.validateCustomAttributesContent(Resource.SIGNING_PROFILE, request.getCustomAttributes());
        List<BaseAttribute> formatterDefinitions = fetchFormatterAttributeDefinitions(request.getWorkflow());
        SigningProfileDto created = self.persistCreate(request, formatterDefinitions);
        evictSigningProfileCache(created.getName());
        return created;
    }

    @Transactional
    SigningProfileDto persistCreate(SigningProfileRequestDto request, List<BaseAttribute> formatterDefinitions)
            throws AttributeException, NotFoundException {
        SigningProfile profile = new SigningProfile();
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
        profile.setLatestVersion(1);

        SigningProfileVersion v1 = new SigningProfileVersion();
        v1.setVersion(1);
        applyWorkflow(profile, v1, request.getWorkflow());
        applyScheme(profile, v1, request.getSigningScheme());
        profile = signingProfileRepository.save(profile);
        v1.setSigningProfile(profile);
        signingProfileVersionRepository.save(v1);

        List<ResponseAttribute> customAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid(), request.getCustomAttributes());
        List<ResponseAttribute> signingOperationAttributes = persistSigningOperationAttributes(profile, v1, request.getSigningScheme());
        List<ResponseAttribute> signatureFormatterConnectorAttributes = persistSignatureFormatterConnectorAttributes(profile, v1, request.getWorkflow(), formatterDefinitions);
        return SigningProfileMapper.toDto(profile, v1, customAttributes, signingOperationAttributes, signatureFormatterConnectorAttributes);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Update (lenient version bump with advisory locking)
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public SigningProfileDto updateSigningProfile(SecuredUUID uuid, SigningProfileRequestDto request)
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        validateSigningSchemeCoherence(request.getSigningScheme());
        attributeEngine.validateCustomAttributesContent(Resource.SIGNING_PROFILE, request.getCustomAttributes());
        List<BaseAttribute> formatterDefinitions = fetchFormatterAttributeDefinitions(request.getWorkflow());
        return self.persistUpdate(uuid, request, formatterDefinitions);
    }

    @Transactional
    SigningProfileDto persistUpdate(SecuredUUID uuid, SigningProfileRequestDto request, List<BaseAttribute> formatterDefinitions)
            throws AlreadyExistException, AttributeException, NotFoundException {
        // Acquire advisory lock before the bump decision to prevent race conditions
        signingProfileVersionRepository.acquireAdvisoryLock("signing-profile:" + uuid.getValue());

        SigningProfile profile = findByUuid(uuid);
        // Capture the previous name under the advisory lock so concurrent renames evict the committed source name.
        String oldName = profile.getName();

        Optional<SigningProfile> existingWithSameName = signingProfileRepository.findByName(request.getName());
        if (existingWithSameName.isPresent() && !existingWithSameName.get().getUuid().equals(profile.getUuid())) {
            throw new AlreadyExistException("Signing Profile with name '" + request.getName() + "' already exists.");
        }

        profile.setName(request.getName());
        profile.setDescription(request.getDescription());

        int nextVersion = profile.getLatestVersion() + 1;
        profile.setLatestVersion(nextVersion);
        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(nextVersion);

        applyWorkflow(profile, version, request.getWorkflow());
        applyScheme(profile, version, request.getSigningScheme());
        profile = signingProfileRepository.save(profile);
        signingProfileVersionRepository.save(version);

        List<ResponseAttribute> customAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid(), request.getCustomAttributes());
        List<ResponseAttribute> signingOperationAttributes = persistSigningOperationAttributes(profile, version, request.getSigningScheme());
        List<ResponseAttribute> signatureFormatterConnectorAttributes = persistSignatureFormatterConnectorAttributes(profile, version, request.getWorkflow(), formatterDefinitions);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(oldName);
        evictSigningProfileCache(profile.getName());
        return SigningProfileMapper.toDto(profile, version, customAttributes, signingOperationAttributes, signatureFormatterConnectorAttributes);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DELETE)
    @Transactional
    public void deleteSigningProfile(SecuredUUID uuid) throws NotFoundException, ValidationException {
        SigningProfile profile = findByUuid(uuid);
        deleteSigningProfile(profile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteSigningProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            SigningProfile profile = null;
            try {
                profile = findByUuid(uuid);
                self.deleteInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to delete Signing Profile {}", uuid, e);
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Delete failed"));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(SigningProfile profile) throws ValidationException {
        deleteSigningProfile(profile);
    }

    private void deleteSigningProfile(SigningProfile signingProfile) throws ValidationException {
        SecuredList<TspProfile> tspProfiles = tspProfileService.listTspProfilesUsingSigningProfileAsDefault(
                SecuredUUID.fromUUID(signingProfile.getUuid()), SecurityFilter.create());
        if (!tspProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(String.format(
                            "Cannot delete Signing Profile: used as default signing profile by TSP Profiles (%d): %s",
                            tspProfiles.size(),
                            tspProfiles.getAllowed().stream().map(TspProfile::getName).collect(Collectors.joining(", "))
                    ))
            );
        }

        signingProfileWriter.deleteAllVersionsBySigningProfileUuid(signingProfile.getUuid());
        signingProfileRepository.delete(signingProfile);
        attributeEngine.deleteObjectAttributeContent(Resource.SIGNING_PROFILE, signingProfile.getUuid());
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(signingProfile.getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Enable / disable
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ENABLE)
    @Transactional
    public void enableSigningProfile(SecuredUUID uuid) throws NotFoundException {
        enableSigningProfile(findByUuid(uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ENABLE)
    public List<BulkActionMessageDto> bulkEnableSigningProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            SigningProfile profile = null;
            try {
                profile = findByUuid(uuid);
                self.enableInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to enable Signing Profile {}", uuid, e);
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Enable failed"));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void enableInOwnTransaction(SigningProfile profile) {
        enableSigningProfile(profile);
    }

    private void enableSigningProfile(SigningProfile p) {
        p.setEnabled(true);
        signingProfileRepository.save(p);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(p.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ENABLE)
    @Transactional
    public void disableSigningProfile(SecuredUUID uuid) throws NotFoundException {
        disableSigningProfile(findByUuid(uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ENABLE)
    public List<BulkActionMessageDto> bulkDisableSigningProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            SigningProfile profile = null;
            try {
                profile = findByUuid(uuid);
                self.disableInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to disable Signing Profile {}", uuid, e);
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Disable failed"));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void disableInOwnTransaction(SigningProfile profile) {
        disableSigningProfile(profile);
    }

    private void disableSigningProfile(SigningProfile p) {
        p.setEnabled(false);
        signingProfileRepository.save(p);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(p.getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Protocol activation — TSP
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public TspActivationDetailDto getTspActivationDetails(SecuredUUID uuid) throws NotFoundException {
        SigningProfile signingProfile = findByUuid(uuid);
        return SigningProfileMapper.toTspActivationDto(signingProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.UPDATE)
    @Transactional
    public TspActivationDetailDto activateTsp(SecuredUUID signingProfileUuid, SecuredUUID tspProfileUuid) throws NotFoundException {
        SigningProfile signingProfile = findByUuid(signingProfileUuid);
        validateSupportedProtocol(signingProfile.getWorkflowType(), SigningProtocol.TSP);
        TspProfile tspProfile = tspProfileService.getTspProfileEntity(tspProfileUuid);
        signingProfile.setTspProfile(tspProfile);
        signingProfileRepository.save(signingProfile);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(signingProfile.getName());
        return SigningProfileMapper.toTspActivationDto(signingProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.UPDATE)
    @Transactional
    public void deactivateTsp(SecuredUUID uuid) throws NotFoundException {
        SigningProfile profile = findByUuid(uuid);
        profile.setTspProfile(null);
        signingProfileRepository.save(profile);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(profile.getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private SigningProfile findByUuid(SecuredUUID uuid) throws NotFoundException {
        return signingProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("Signing Profile not found: " + uuid));
    }

    private void validateSupportedProtocol(SigningWorkflowType workflowType, SigningProtocol protocol) {
        Set<SigningProtocol> supported = SUPPORTED_PROTOCOLS.getOrDefault(workflowType, EnumSet.noneOf(SigningProtocol.class));
        if (!supported.contains(protocol)) {
            throw new ValidationException(protocol.getCode() + " is not supported for workflow type " + workflowType.getCode());
        }
    }

    private void validateSigningSchemeCoherence(SigningSchemeRequestDto scheme) {
        if (scheme.getSigningScheme() == SigningScheme.MANAGED
                && !(scheme instanceof ManagedSigningRequestSchemeInterface)) {
            throw new ValidationException("MANAGED signing scheme must specify managedSigningType");
        }
        if (scheme.getSigningScheme() == SigningScheme.DELEGATED
                && scheme instanceof ManagedSigningRequestSchemeInterface) {
            throw new ValidationException("DELEGATED signing scheme must not have managedSigningType");
        }
    }

    /**
     * Applies the signing scheme request to both the profile header (cache column) and the version entity (authoritative).
     */
    private void applyScheme(SigningProfile p, SigningProfileVersion version, SigningSchemeRequestDto scheme) throws NotFoundException {
        p.setSigningScheme(scheme.getSigningScheme()); // cache column
        version.setSigningScheme(scheme.getSigningScheme());
        version.setManagedSigningType(null);
        version.setTokenProfile(null);
        version.setCertificate(null);
        version.setRaProfile(null);
        version.setCsrTemplateUuid(null);
        version.setDelegatedSignerConnector(null);

        switch (scheme) {
            case StaticKeyManagedSigningRequestDto s -> {
                version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
                Certificate certificate =
                        certificateService.getCertificateEntity(SecuredUUID.fromUUID(s.getCertificateUuid()));
                if (CertificateUtil.isCertificateDigitalSigningAcceptable(certificate, p.getWorkflowType(), Boolean.TRUE.equals(version.getQualifiedTimestamp()))) {
                    version.setCertificate(certificate);
                } else {
                    throw new ValidationException("Certificate " + certificate.getUuid() + " is not eligible for signing workflow type " + p.getWorkflowType());
                }
                if (!certificateService.getCertificateChain(SecuredUUID.fromUUID(certificate.getUuid()), false).isCompleteChain()) {
                    throw new ValidationException("Certificate " + certificate.getUuid() + " does not represent a complete certificate chain");
                }
            }
            case OneTimeKeyManagedSigningRequestDto s -> {
                version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
                TokenProfile tokenProfile = tokenProfileService.getTokenProfileEntity(SecuredUUID.fromUUID(s.getTokenProfileUuid()));
                version.setTokenProfile(tokenProfile);
                RaProfile raProfile = raProfileService.getRaProfileEntity(SecuredUUID.fromUUID(s.getRaProfileUuid()));
                version.setRaProfile(raProfile);
                version.setCsrTemplateUuid(s.getCsrTemplateUuid());
            }
            case DelegatedSigningRequestDto s -> {
                Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromUUID(s.getConnectorUuid()));
                version.setDelegatedSignerConnector(connector);
            }
            default ->
                    throw new IllegalStateException("Unexpected type for Signing Scheme: " + scheme.getSigningScheme());
        }
    }

    /**
     * Applies the workflow request to both the profile header (cache columns / unversioned fields)
     * and the version entity (authoritative versioned fields).
     */
    private void applyWorkflow(SigningProfile p, SigningProfileVersion version, WorkflowRequestDto workflow) throws NotFoundException {
        p.setTimeQualityConfiguration(null);
        p.setWorkflowType(workflow.getType()); // cache column
        version.setWorkflowType(workflow.getType());
        version.setSignatureFormatterConnector(null);
        version.setQualifiedTimestamp(null);
        version.setDefaultPolicyId(null);
        version.setAllowedPolicyIds(new ArrayList<>());
        version.setAllowedDigestAlgorithms(new ArrayList<>());
        version.setValidateTokenSignature(null);

        switch (workflow) {
            case ContentSigningWorkflowRequestDto w -> {
                if (w.getSignatureFormatterConnectorUuid() == null) {
                    throw new ValidationException("Signature formatter connector is required for content signing workflow");
                }
                Connector contentConnector =
                        connectorService.getConnectorEntity(SecuredUUID.fromUUID(w.getSignatureFormatterConnectorUuid()));
                validateFormatterConnectorFeature(contentConnector, FeatureFlag.CONTENT_SIGNING, SigningWorkflowType.CONTENT_SIGNING);
                version.setSignatureFormatterConnector(contentConnector);
            }
            case RawSigningWorkflowRequestDto ignored -> {
                // RawSigningWorkflowRequestDto has no signatureFormatterConnectorUuid field — no formatter is allowed
            }
            case TimestampingWorkflowRequestDto w -> {
                if (w.getSignatureFormatterConnectorUuid() == null) {
                    throw new ValidationException("Signature formatter connector is required for timestamping workflow");
                }
                Connector tsaConnector =
                        connectorService.getConnectorEntity(SecuredUUID.fromUUID(w.getSignatureFormatterConnectorUuid()));
                validateFormatterConnectorFeature(tsaConnector, FeatureFlag.TIMESTAMPING, SigningWorkflowType.TIMESTAMPING);
                version.setSignatureFormatterConnector(tsaConnector);
                version.setQualifiedTimestamp(w.getQualifiedTimestamp());
                version.setDefaultPolicyId(w.getDefaultPolicyId());
                version.setAllowedPolicyIds(w.getAllowedPolicyIds() != null ? w.getAllowedPolicyIds() : new ArrayList<>());
                if (w.getAllowedDigestAlgorithms() != null) {
                    version.setAllowedDigestAlgorithms(w.getAllowedDigestAlgorithms().stream().map(DigestAlgorithm::getCode).toList());
                }
                version.setValidateTokenSignature(w.getValidateTokenSignature());
                // Time Quality Configuration is unversioned
                if (w.getTimeQualityConfigurationUuid() != null) {
                    TimeQualityConfiguration tqc = timeQualityConfigurationRepository
                            .findByUuid(SecuredUUID.fromUUID(w.getTimeQualityConfigurationUuid()))
                            .orElseThrow(() -> new NotFoundException(TimeQualityConfiguration.class, w.getTimeQualityConfigurationUuid()));
                    p.setTimeQualityConfiguration(tqc);
                }
            }
            default -> throw new IllegalStateException("Unexpected type for Signing Workflow: " + workflow);
        }
    }

    private void validateFormatterConnectorFeature(Connector connector, FeatureFlag requiredFeature, SigningWorkflowType workflowType) {
        boolean hasFeature = connector.getInterfaces().stream()
                .filter(i -> ConnectorInterface.SIGNATURE_FORMATTING.equals(i.getInterfaceCode()))
                .anyMatch(i -> i.getFeatures() != null && i.getFeatures().contains(requiredFeature));
        if (!hasFeature) {
            throw new ValidationException("Formatter connector '%s' does not support the '%s' feature required for %s workflow"
                    .formatted(connector.getName(), requiredFeature.getLabel(), workflowType.getLabel()));
        }
    }

    /**
     * Builds a full DTO from a version row. Reads attributes from AttributeEngine using the version number.
     */
    private SigningProfileDto buildDtoFromVersion(SigningProfile profile, SigningProfileVersion spv) {
        List<ResponseAttribute> customAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid());
        List<ResponseAttribute> signingOperationAttributes = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .operation(AttributeOperation.SIGN)
                        .version(spv.getVersion()).build());
        List<ResponseAttribute> signatureFormatterConnectorAttributes = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .connector(spv.getSignatureFormatterConnectorUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER)
                        .version(spv.getVersion()).build());
        return SigningProfileMapper.toDto(profile, spv, customAttributes, signingOperationAttributes, signatureFormatterConnectorAttributes);
    }

    private SigningProfileDto buildDtoFromProfile(SigningProfile profile) {
        SigningProfileVersion current = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(profile.getUuid(), profile.getLatestVersion())
                .orElseThrow(() -> new IllegalStateException("No version row found for signing profile " + profile.getUuid() + " version " + profile.getLatestVersion()));
        return buildDtoFromVersion(profile, current);
    }

    private List<ResponseAttribute> persistSigningOperationAttributes(SigningProfile signingProfile, SigningProfileVersion version, SigningSchemeRequestDto signingScheme)
            throws AttributeException, NotFoundException {
        if (signingScheme instanceof StaticKeyManagedSigningRequestDto staticKeyScheme) {
            List<RequestAttribute> signingOperationAttributes = staticKeyScheme.getSigningOperationAttributes();
            List<BaseAttribute> definitions = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(version.getCertificate().getKey().getUuid()))
                    .stream()
                    .findFirst()
                    .map(item -> cryptographicOperationService.listSignatureAttributes(item.getKeyAlgorithm()))
                    .orElse(List.of());

            // The signing operation attributes are Core-internal (not connector-owned), so connectorUuid is null.
            attributeEngine.validateUpdateDataAttributes(null, AttributeOperation.SIGN, definitions, signingOperationAttributes);
            return attributeEngine.replaceObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, signingProfile.getUuid())
                            .operation(AttributeOperation.SIGN)
                            .version(version.getVersion()).build(),
                    signingOperationAttributes);
        }
        // For non-STATIC_KEY schemes, clean up any attributes that may remain for the current version.
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA,
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, signingProfile.getUuid())
                        .operation(AttributeOperation.SIGN)
                        .version(version.getVersion()).build());
        return List.of();
    }

    private List<ResponseAttribute> persistSignatureFormatterConnectorAttributes(SigningProfile p,
                                                                                 SigningProfileVersion version,
                                                                                 WorkflowRequestDto workflow,
                                                                                 List<BaseAttribute> formatterDefinitions)
            throws AttributeException, NotFoundException {
        return switch (workflow) {
            case ContentSigningWorkflowRequestDto w -> {
                attributeEngine.validateUpdateDataAttributes(w.getSignatureFormatterConnectorUuid(), AttributeOperation.WORKFLOW_FORMATTER, formatterDefinitions, w.getSignatureFormatterConnectorAttributes());
                yield attributeEngine.replaceObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, p.getUuid())
                                .connector(w.getSignatureFormatterConnectorUuid())
                                .operation(AttributeOperation.WORKFLOW_FORMATTER)
                                .version(version.getVersion()).build(),
                        w.getSignatureFormatterConnectorAttributes());
            }
            case RawSigningWorkflowRequestDto ignored -> {
                // Raw signing has no formatter; clean up any formatter attributes that may remain for this version.
                attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA,
                        ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, p.getUuid())
                                .operation(AttributeOperation.WORKFLOW_FORMATTER)
                                .version(version.getVersion()).build());
                yield null;
            }
            case TimestampingWorkflowRequestDto w -> {
                attributeEngine.validateUpdateDataAttributes(w.getSignatureFormatterConnectorUuid(), AttributeOperation.WORKFLOW_FORMATTER, formatterDefinitions, w.getSignatureFormatterConnectorAttributes());
                yield attributeEngine.replaceObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, p.getUuid())
                                .connector(w.getSignatureFormatterConnectorUuid())
                                .operation(AttributeOperation.WORKFLOW_FORMATTER)
                                .version(version.getVersion()).build(),
                        w.getSignatureFormatterConnectorAttributes());
            }
            default -> throw new IllegalStateException("Unexpected type for Signing Workflow: " + workflow);
        };
    }

    /**
     * Fetches formatter attribute definitions from the connector without persisting them.
     * Definitions are persisted later inside the transaction by {@link #persistSignatureFormatterConnectorAttributes}
     * via {@link AttributeEngine#validateUpdateDataAttributes}, which keeps the definition upsert and content write atomic.
     */
    private List<BaseAttribute> fetchFormatterAttributeDefinitions(WorkflowRequestDto workflow) throws ConnectorException, NotFoundException {
        return switch (workflow) {
            case ContentSigningWorkflowRequestDto w ->
                    fetchFormatterAttributeDefinitions(w.getSignatureFormatterConnectorUuid());
            case TimestampingWorkflowRequestDto w ->
                    fetchFormatterAttributeDefinitions(w.getSignatureFormatterConnectorUuid());
            default -> List.of();
        };
    }

    private List<BaseAttribute> fetchFormatterAttributeDefinitions(UUID connectorUuid) throws ConnectorException, NotFoundException {
        ApiClientConnectorInfo apiClientInfo = connectorService.getConnectorForApiClient(connectorUuid);
        return connectorApiFactory.getSignatureFormatterApiClient(apiClientInfo).listFormatterAttributes(apiClientInfo);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ResourceExtensionService
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return signingProfileRepository.findResourceObject(objectUuid, SigningProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return signingProfileRepository.findResourceObject(objectUuid.getValue(), SigningProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return signingProfileRepository.listResourceObjects(filter, SigningProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(readOnly = true)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        findByUuid(uuid);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Dependencies
    // ──────────────────────────────────────────────────────────────────────────

    @Lazy
    @Autowired
    public void setSelf(SigningProfileServiceImpl self) {
        this.self = self;
    }

    @Autowired
    public void setCacheEvictor(CacheEvictor cacheEvictor) {
        this.cacheEvictor = cacheEvictor;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCryptographicOperationService(CryptographicOperationService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setTokenProfileService(TokenProfileService tokenProfileService) {
        this.tokenProfileService = tokenProfileService;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setCryptographicKeyItemRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Autowired
    public void setSigningProfileRepository(SigningProfileRepository signingProfileRepository) {
        this.signingProfileRepository = signingProfileRepository;
    }

    @Autowired
    public void setSigningProfileVersionRepository(SigningProfileVersionRepository signingProfileVersionRepository) {
        this.signingProfileVersionRepository = signingProfileVersionRepository;
    }

    @Autowired
    public void setSigningProfileWriter(SigningProfileWriter signingProfileWriter) {
        this.signingProfileWriter = signingProfileWriter;
    }

    @Autowired
    public void setTimeQualityConfigurationRepository(TimeQualityConfigurationRepository timeQualityConfigurationRepository) {
        this.timeQualityConfigurationRepository = timeQualityConfigurationRepository;
    }

    @Autowired
    @Lazy
    public void setTspProfileService(TspProfileService tspProfileService) {
        this.tspProfileService = tspProfileService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }
}
