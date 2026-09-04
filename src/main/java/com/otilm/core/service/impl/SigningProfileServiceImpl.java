package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.DelegatedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningRequestSchemeInterface;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.scheme.SigningSchemeRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.StaticKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.RawSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.TimestampingWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.WorkflowRequestDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.Audited_;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningProfile_;
import com.otilm.core.dao.entity.signing.TimeQualityConfiguration;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.mapper.signing.SigningProfileMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.ConnectorInternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.SigningRecordInternalService;
import com.otilm.core.service.TokenProfileInternalService;
import com.otilm.core.service.TspProfileInternalService;
import com.otilm.core.service.model.SecuredList;
import com.otilm.core.service.writer.SigningProfileWriter;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingAttributes;
import com.otilm.core.signing.contentsigning.profile.ContentSigningWorkflowValidator;
import com.otilm.core.signing.contentsigning.profile.TimestampSourceRequests;
import com.otilm.core.util.CertificateEligibilityUtil;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.annotation.Nullable;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
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

@Service(Resource.Codes.SIGNING_PROFILE)
@Slf4j
public class SigningProfileServiceImpl implements SigningProfileExternalService, SigningProfileInternalService {

    /**
     * Defines which signing protocols an operator may enable per workflow type. Only protocols a client can actually
     * reach belong here.
     */
    private static final Map<SigningWorkflowType, Set<SigningProtocol>> SUPPORTED_PROTOCOLS = Map
            .of(SigningWorkflowType.TIMESTAMPING, EnumSet.of(SigningProtocol.TSP));

    private SigningProfileServiceImpl self;
    private CryptographicOperationInternalService cryptographicOperationService;
    private CertificateInternalService certificateService;
    private ConnectorInternalService connectorService;
    private TokenProfileInternalService tokenProfileService;
    private RaProfileInternalService raProfileService;
    private SigningRecordExternalService signingRecordService;
    private SigningRecordInternalService signingRecordInternalService;

    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private SigningProfileRepository signingProfileRepository;
    private SigningProfileVersionRepository signingProfileVersionRepository;
    private SigningProfileWriter signingProfileWriter;
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private TspProfileInternalService tspProfileService;
    private AttributeEngine attributeEngine;
    private ConnectorApiFactory connectorApiFactory;
    private CacheEvictor cacheEvictor;
    private ClusterOperationSynchronizer clusterSynchronizer;
    private ContentSigningWorkflowValidator contentSigningWorkflowValidator;
    private ContentSigningFormattingAttributes contentSigningFormattingAttributes;

    // ──────────────────────────────────────────────────────────────────────────
    // List / search
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine
                .getResourceSearchableFields(Resource.SIGNING_PROFILE, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List
                .of(SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_NAME),
                        SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_ENABLED),
                        SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_SIGNING_SCHEME),
                        SearchHelper.prepareSearch(FilterField.SIGNING_PROFILE_WORKFLOW_TYPE),
                        SearchHelper
                                .prepareSearch(FilterField.SIGNING_PROFILE_TSP_PROFILE,
                                        tspProfileService.findAllNames()),
                        SearchHelper
                                .prepareSearch(FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION,
                                        timeQualityConfigurationRepository.findAllNames())));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @AnyPrincipalEndpoint
    public List<SigningProtocol> listSupportedProtocols(SigningWorkflowType workflowType) {
        return List.copyOf(SUPPORTED_PROTOCOLS.getOrDefault(workflowType, EnumSet.noneOf(SigningProtocol.class)));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningProfileListDto> listSigningProfiles(SearchRequestDto request,
            SecurityFilter filter) {
        RequestValidatorHelper.revalidateSearchRequestDto(request, Resource.SIGNING_PROFILE);
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        TriFunction<Root<SigningProfile>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb,
                cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters(), contentFilter);
        List<SigningProfileListDto> profiles = signingProfileRepository
                .findUsingSecurityFilter(filter, List.of(), predicate, p,
                        (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
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
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SimplifiedSigningProfileDto> listSigningProfilesAssociatedTimeQualityConfiguration(
            SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter) {
        return listSigningProfileEntitiesAssociatedTimeQualityConfiguration(timeQualityConfigurationUuid, filter)
                .getAllowed()
                .stream()
                .map(SigningProfileMapper::toSimpleDto)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public SecuredList<SigningProfile> listSigningProfileEntitiesAssociatedTimeQualityConfiguration(
            SecuredUUID timeQualityConfigurationUuid, SecurityFilter filter) {
        List<SigningProfile> signingProfiles = signingProfileRepository
                .findAllByTimeQualityConfigurationUuid(timeQualityConfigurationUuid.getValue());
        return SecuredList.fromFilter(filter, signingProfiles);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public SecuredList<SigningProfile> listSigningProfilesAssociatedWithTsp(SecuredUUID tspProfileUuid,
            SecurityFilter filter) {
        List<SigningProfile> signingProfiles = signingProfileRepository
                .findAllByTspProfileUuid(tspProfileUuid.getValue());
        return SecuredList.fromFilter(filter, signingProfiles);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.LIST)
    public List<CertificateDto> listSigningCertificates(SigningWorkflowType signingWorkflowType,
            boolean qualifiedTimestamp, boolean requireNonRepudiation, Set<String> requiredExtendedKeyUsageOids) {
        return certificateService
                .listDigitalSigningCertificates(SecurityFilter.create(), signingWorkflowType, qualifiedTimestamp,
                        CertificatePurposeRequirements.of(requireNonRepudiation, requiredExtendedKeyUsageOids));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public List<BaseAttribute> listSignatureAttributesForCertificate(SecuredUUID certificateUuid)
            throws NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(certificateUuid);
        if (certificate.getKey() == null) {
            return List.of();
        }
        return cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(certificate.getKey().getUuid()))
                .stream()
                .findFirst()
                .map(item -> cryptographicOperationService.listSignatureAttributes(item.getKeyAlgorithm()))
                .orElse(List.of());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listSignatureFormattingConnectorAttributes(UUID connectorUuid,
            SecuredUUID signingProfileUuid) throws NotFoundException, ConnectorException, AttributeException {
        return fetchFormattingAttributeDefinitions(connectorUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listContentSigningFormattingConnectorAttributes(UUID connectorUuid,
            SignatureFamily family, SignatureLevel maxLevel, SecuredUUID signingProfileUuid)
            throws NotFoundException, ConnectorException, AttributeException {
        ContentSigningWorkflowValidator
                .requireConnectorServes(
                        connectorService.getConnectorEntityWithInterfaces(SecuredUUID.fromUUID(connectorUuid)), family,
                        maxLevel);
        return contentSigningFormattingAttributes
                .aggregate(connectorService.getConnectorForApiClient(connectorUuid), maxLevel);
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
    public SigningProfileModel<? extends SigningWorkflow, ? extends SigningSchemeModel> getSigningProfileModel(
            String name) throws NotFoundException {
        return self.loadSigningProfileModel(name);
    }

    /** Cache loader. No authorization annotation by design. */
    @Override
    @Cacheable(value = CacheConfig.SIGNING_PROFILE_CACHE, key = "#name", sync = true)
    @Transactional(readOnly = true, noRollbackFor = NotFoundException.class)
    public SigningProfileModel<?, ?> loadSigningProfileModel(String name) throws NotFoundException {
        SigningProfile profile = signingProfileRepository
                .findByName(name)
                .orElseThrow(() -> new NotFoundException(SigningProfile.class, name));
        SigningProfileVersion currentVersion = profile
                .getVersions()
                .stream()
                .filter(v -> v.getVersion() == profile.getLatestVersion())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Signing Profile '" + name + "' has no row for latestVersion " + profile.getLatestVersion()));

        List<RequestAttribute> signingOperationAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .operation(AttributeOperation.SIGN)
                        .version(currentVersion.getVersion())
                        .build());
        List<RequestAttribute> signatureFormattingConnectorAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .connector(currentVersion.getSignatureFormattingConnectorUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTING)
                        .version(currentVersion.getVersion())
                        .build());

        return switch (currentVersion.getWorkflowType()) {
            case TIMESTAMPING -> SigningProfileMapper
                    .toManagedTimestampingModel(profile, currentVersion, signingOperationAttributes,
                            signatureFormattingConnectorAttributes);
            case CONTENT_SIGNING -> SigningProfileMapper
                    .toManagedContentSigningModel(profile, currentVersion, signingOperationAttributes,
                            signatureFormattingConnectorAttributes);
            case RAW_SIGNING -> throw new IllegalArgumentException(
                    "Signing Profile '%s' uses the RAW_SIGNING workflow, which does not support model retrieval yet"
                            .formatted(name));
        };
    }

    @Override
    public Optional<TspProfileModel> resolveTspProfileForSigningProfileAuthentication(String signingProfileName)
            throws NotFoundException {
        String linkedTspProfileName = self.loadLinkedTspProfileName(signingProfileName);
        if (linkedTspProfileName == null) {
            return Optional.empty();
        }
        return Optional.of(tspProfileService.resolveTspProfileForAuthentication(linkedTspProfileName));
    }

    // Self-invoked helper to apply @Transactional.
    @Transactional(readOnly = true)
    String loadLinkedTspProfileName(String signingProfileName) throws NotFoundException {
        SigningProfile profile = signingProfileRepository
                .findByName(signingProfileName)
                .orElseThrow(() -> new NotFoundException(SigningProfile.class, signingProfileName));
        if (profile.getTspProfileUuid() == null) {
            return null;
        }
        TspProfile tspProfile = profile.getTspProfile();
        if (tspProfile == null) {
            throw new NotFoundException(TspProfile.class, profile.getTspProfileUuid());
        }
        return tspProfile.getName();
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
        validateContentSigningWorkflow(request, null);
        List<BaseAttribute> formattingDefinitions = fetchFormattingAttributeDefinitions(request.getWorkflow());
        SigningProfileDto created = self.persistCreate(request, formattingDefinitions);
        evictSigningProfileCache(created.getName());
        return created;
    }

    @Transactional
    SigningProfileDto persistCreate(SigningProfileRequestDto request, List<BaseAttribute> formattingDefinitions)
            throws AttributeException, NotFoundException {
        SigningProfile profile = new SigningProfile();
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
        profile.setLatestVersion(1);

        SigningProfileVersion v1 = new SigningProfileVersion();
        v1.setVersion(1);
        applyWorkflow(profile, v1, request.getWorkflow(), request.getSigningScheme().getSigningScheme());
        applyScheme(profile, v1, request.getSigningScheme());
        applyRecordPolicyToVersion(v1, request.getRecordPolicy());
        profile = signingProfileRepository.save(profile);
        v1.setSigningProfile(profile);
        signingProfileVersionRepository.save(v1);

        List<ResponseAttribute> customAttributes = attributeEngine
                .updateObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid(),
                        request.getCustomAttributes());
        List<ResponseAttribute> signingOperationAttributes = persistSigningOperationAttributes(profile, v1,
                request.getSigningScheme());
        List<ResponseAttribute> signatureFormattingConnectorAttributes = persistSignatureFormattingConnectorAttributes(
                profile, v1, request.getWorkflow(), formattingDefinitions);
        return SigningProfileMapper
                .toDto(profile, v1, customAttributes, signingOperationAttributes,
                        signatureFormattingConnectorAttributes, timestampSourceProfileName(v1));
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
        validateContentSigningWorkflow(request, uuid.getValue());
        List<BaseAttribute> formattingDefinitions = fetchFormattingAttributeDefinitions(request.getWorkflow());
        return self.persistUpdate(uuid, request, formattingDefinitions);
    }

    @Transactional
    SigningProfileDto persistUpdate(SecuredUUID uuid, SigningProfileRequestDto request,
            List<BaseAttribute> formattingDefinitions)
            throws AlreadyExistException, AttributeException, NotFoundException {
        // Serialize the bump decision per profile to prevent concurrent updates from racing.
        clusterSynchronizer.lock("signing-profile:" + uuid.getValue());

        SigningProfile profile = findByUuid(uuid);
        // Capture the previous name under the advisory lock so concurrent renames evict the committed source name.
        String oldName = profile.getName();

        Optional<SigningProfile> existingWithSameName = signingProfileRepository.findByName(request.getName());
        if (existingWithSameName.isPresent() && !existingWithSameName.get().getUuid().equals(profile.getUuid())) {
            throw new AlreadyExistException("Signing Profile with name '" + request.getName() + "' already exists.");
        }

        profile.setName(request.getName());
        profile.setDescription(request.getDescription());

        // Lenient version bump: bump if signing records exist for the current version, or if record policy fields
        // changed.
        int latestVersion = profile.getLatestVersion();
        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(profile.getUuid(), latestVersion)
                .orElseThrow(() -> new NotFoundException("Signing Profile version " + latestVersion + " not found"));
        boolean recordsExist = signingRecordInternalService
                .doesSigningRecordExistInternal(profile.getUuid(), latestVersion);
        boolean policyRecordDifferent = recordPolicyDiffersFromVersion(currentVersion, request.getRecordPolicy());
        boolean bump = recordsExist || policyRecordDifferent;

        SigningProfileVersion version;
        if (bump) {
            profile.setLatestVersion(profile.getLatestVersion() + 1);
            version = new SigningProfileVersion();
        } else {
            version = currentVersion;
        }
        version.setSigningProfile(profile);
        version.setVersion(profile.getLatestVersion());

        applyWorkflow(profile, version, request.getWorkflow(), request.getSigningScheme().getSigningScheme());
        applyScheme(profile, version, request.getSigningScheme());
        applyRecordPolicyToVersion(version, request.getRecordPolicy());
        profile = signingProfileRepository.save(profile);
        signingProfileVersionRepository.save(version);

        List<ResponseAttribute> customAttributes = attributeEngine
                .updateObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid(),
                        request.getCustomAttributes());
        List<ResponseAttribute> signingOperationAttributes = persistSigningOperationAttributes(profile, version,
                request.getSigningScheme());
        List<ResponseAttribute> signatureFormattingConnectorAttributes = persistSignatureFormattingConnectorAttributes(
                profile, version, request.getWorkflow(), formattingDefinitions);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(oldName);
        evictSigningProfileCache(profile.getName());
        return SigningProfileMapper
                .toDto(profile, version, customAttributes, signingOperationAttributes,
                        signatureFormattingConnectorAttributes, timestampSourceProfileName(version));
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
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(), profile != null ? profile.getName() : "", e,
                                        "Delete failed"));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(SigningProfile profile) throws ValidationException {
        deleteSigningProfile(profile);
    }

    /**
     * Superseded version rows are retained for audit and cannot be edited. The hold is released only by deleting the
     * referencing profile.
     */
    private List<String> timestampSourceBlockers(UUID timestampSourceProfileUuid) {
        List<String> latestVersionNames = signingProfileVersionRepository
                .findSigningProfileNamesUsingTimestampSourceProfileInLatestVersion(timestampSourceProfileUuid);
        List<String> supersededOnlyNames = new ArrayList<>(signingProfileVersionRepository
                .findSigningProfileNamesUsingTimestampSourceProfile(timestampSourceProfileUuid));
        supersededOnlyNames.removeAll(latestVersionNames);

        List<String> blockers = new ArrayList<>();
        if (!latestVersionNames.isEmpty()) {
            blockers
                    .add("it is named as the timestamp source by Signing Profile(s) (repoint them, or lower their maxLevel to SIGNED, to release it): "
                            + String.join(", ", latestVersionNames));
        }
        if (!supersededOnlyNames.isEmpty()) {
            blockers
                    .add("it is named as the timestamp source only in superseded version(s) of the referencing Signing Profile(s), and a superseded version cannot be edited, so the hold is released only by deleting the referencing profile, which first requires deleting its signing records: "
                            + String.join(", ", supersededOnlyNames));
        }
        return blockers;
    }

    private void deleteSigningProfile(SigningProfile signingProfile) throws ValidationException {
        SecuredList<TspProfile> tspProfiles = tspProfileService
                .listTspProfilesUsingSigningProfileAsDefault(SecuredUUID.fromUUID(signingProfile.getUuid()),
                        SecurityFilter.create());
        if (!tspProfiles.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create(String
                            .format("Cannot delete Signing Profile: used as default signing profile by TSP Profiles (%d): %s",
                                    tspProfiles.size(),
                                    tspProfiles
                                            .getAllowed()
                                            .stream()
                                            .map(TspProfile::getName)
                                            .collect(Collectors.joining(", ")))));
        }

        List<String> timestampSourceBlockers = timestampSourceBlockers(signingProfile.getUuid());
        if (!timestampSourceBlockers.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create(String
                            .format("Cannot delete Signing Profile '%s': %s", signingProfile.getName(),
                                    String.join("; ", timestampSourceBlockers))));
        }

        if (signingRecordInternalService.doesSigningRecordExistForProfileInternal(signingProfile.getUuid())) {
            throw new ValidationException(ValidationError
                    .create(String
                            .format("Cannot delete Signing Profile '%s': it has signing records. Delete the signing records first.",
                                    signingProfile.getName())));
        }

        signingProfileWriter.deleteAllVersionsBySigningProfileUuid(signingProfile.getUuid());
        commentService.removeObjectComments(Resource.SIGNING_PROFILE, signingProfile.getUuid());
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
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(), profile != null ? profile.getName() : "", e,
                                        "Enable failed"));
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
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(), profile != null ? profile.getName() : "", e,
                                        "Disable failed"));
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
    public TspActivationDetailDto getTspActivationDetails(SecuredUUID uuid, String baseUrl) throws NotFoundException {
        SigningProfile signingProfile = findByUuid(uuid);
        return SigningProfileMapper.toTspActivationDto(signingProfile, baseUrl);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.UPDATE)
    @Transactional
    public TspActivationDetailDto activateTsp(SecuredUUID signingProfileUuid, SecuredUUID tspProfileUuid,
            String baseUrl) throws NotFoundException {
        SigningProfile signingProfile = findByUuid(signingProfileUuid);
        validateSupportedProtocol(signingProfile.getWorkflowType(), SigningProtocol.TSP);
        TspProfile tspProfile = tspProfileService.getTspProfileEntity(tspProfileUuid);
        signingProfile.setTspProfile(tspProfile);
        signingProfileRepository.save(signingProfile);
        tspProfileService.evictAllCachedModels();
        evictSigningProfileCache(signingProfile.getName());
        return SigningProfileMapper.toTspActivationDto(signingProfile, baseUrl);
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
    // Signing records scoped to profile
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecordsForSigningProfile(SecuredUUID uuid,
            SearchRequestDto request, SecurityFilter filter) throws NotFoundException {
        SigningProfile profile = findByUuid(uuid);
        return signingRecordService.listSigningRecordsForProfile(profile.getUuid(), request, filter);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private SigningProfile findByUuid(SecuredUUID uuid) throws NotFoundException {
        return signingProfileRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("Signing Profile not found: " + uuid));
    }

    private void validateSupportedProtocol(SigningWorkflowType workflowType, SigningProtocol protocol) {
        Set<SigningProtocol> supported = SUPPORTED_PROTOCOLS
                .getOrDefault(workflowType, EnumSet.noneOf(SigningProtocol.class));
        if (!supported.contains(protocol)) {
            throw new ValidationException(
                    protocol.getCode() + " is not supported for workflow type " + workflowType.getCode());
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
     * Applies the signing scheme request to both the profile header (cache column) and the version entity
     * (authoritative).
     */
    private void applyScheme(SigningProfile p, SigningProfileVersion version, SigningSchemeRequestDto scheme)
            throws NotFoundException {
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
                Certificate certificate = certificateService
                        .getCertificateEntity(SecuredUUID.fromUUID(s.getCertificateUuid()));
                CertificatePurposeRequirements certificatePurpose = certificatePurposeOf(version);
                if (CertificateEligibilityUtil
                        .isCertificateDigitalSigningAcceptable(certificate, p.getWorkflowType(),
                                Boolean.TRUE.equals(version.getQualifiedTimestamp()), certificatePurpose)) {
                    version.setCertificate(certificate);
                } else {
                    throw new ValidationException(
                            notEligibleMessage(certificate, p.getWorkflowType(), certificatePurpose));
                }
                if (!certificateService
                        .getCertificateChain(SecuredUUID.fromUUID(certificate.getUuid()), false)
                        .isCompleteChain()) {
                    throw new ValidationException("Certificate " + certificate.getUuid()
                            + " does not represent a complete certificate chain");
                }
            }
            case OneTimeKeyManagedSigningRequestDto s -> {
                version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
                TokenProfile tokenProfile = tokenProfileService
                        .getTokenProfileEntity(SecuredUUID.fromUUID(s.getTokenProfileUuid()));
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
     * Applies the workflow request to both the profile header (cache columns / unversioned fields) and the version
     * entity (authoritative versioned fields). The signing scheme decides which of the workflow's fields apply at all.
     */
    private void applyWorkflow(SigningProfile p, SigningProfileVersion version, WorkflowRequestDto workflow,
            SigningScheme signingScheme) throws NotFoundException {
        p.setTimeQualityConfiguration(null);
        p.setWorkflowType(workflow.getType()); // cache column
        version.setWorkflowType(workflow.getType());
        version.setSignatureFormattingConnector(null);
        version.setSignatureFamily(null);
        version.setMaxSignatureLevel(null);
        version.setTimestampSourceProfileUuid(null);
        version.setDocumentSizeCap(null);
        version.setRequireNonRepudiation(false);
        version.setRequiredExtendedKeyUsageOids(new ArrayList<>());
        version.setQualifiedTimestamp(null);
        version.setDefaultPolicyId(null);
        version.setAllowedPolicyIds(new ArrayList<>());
        version.setAllowedDigestAlgorithms(new ArrayList<>());
        version.setValidateTokenSignature(null);

        switch (workflow) {
            case ContentSigningWorkflowRequestDto w -> {
                if (signingScheme == SigningScheme.MANAGED) {
                    applyManagedContentSigning(version, w);
                }
                // Stored for both schemes because the cap belongs to request admission, not to leveling.
                version.setDocumentSizeCap(w.getDocumentSizeCap());
            }
            case RawSigningWorkflowRequestDto ignored -> {
                // RawSigningWorkflowRequestDto has no signatureFormattingConnectorUuid field — no formatting is allowed
            }
            case TimestampingWorkflowRequestDto w -> {
                if (w.getSignatureFormattingConnectorUuid() == null) {
                    throw new ValidationException(
                            "Signature formatting connector is required for timestamping workflow");
                }
                Connector tsaConnector = connectorService
                        .getConnectorEntity(SecuredUUID.fromUUID(w.getSignatureFormattingConnectorUuid()));
                validateFormattingConnectorFeature(tsaConnector, FeatureFlag.TIMESTAMPING,
                        SigningWorkflowType.TIMESTAMPING);
                version.setSignatureFormattingConnector(tsaConnector);
                version.setQualifiedTimestamp(w.getQualifiedTimestamp());
                version.setDefaultPolicyId(w.getDefaultPolicyId());
                version
                        .setAllowedPolicyIds(
                                w.getAllowedPolicyIds() != null ? w.getAllowedPolicyIds() : new ArrayList<>());
                if (w.getAllowedDigestAlgorithms() != null) {
                    version
                            .setAllowedDigestAlgorithms(
                                    w.getAllowedDigestAlgorithms().stream().map(DigestAlgorithm::getCode).toList());
                }
                version.setValidateTokenSignature(w.getValidateTokenSignature());
                // Time Quality Configuration is unversioned
                if (w.getTimeQualityConfigurationUuid() != null) {
                    TimeQualityConfiguration tqc = timeQualityConfigurationRepository
                            .findByUuid(SecuredUUID.fromUUID(w.getTimeQualityConfigurationUuid()))
                            .orElseThrow(() -> new NotFoundException(TimeQualityConfiguration.class,
                                    w.getTimeQualityConfigurationUuid()));
                    p.setTimeQualityConfiguration(tqc);
                }
            }
            default -> throw new IllegalStateException("Unexpected type for Signing Workflow: " + workflow);
        }
    }

    /**
     * Runs outside the persistence transaction, so a request the contract already refuses never reaches a connector
     * round-trip: {@code fetchFormattingAttributeDefinitions} calls the named provider straight after this.
     */
    private void validateContentSigningWorkflow(SigningProfileRequestDto request, @Nullable UUID targetProfileUuid)
            throws NotFoundException {
        if (!(request.getWorkflow() instanceof ContentSigningWorkflowRequestDto w)) {
            return;
        }
        if (request.getSigningScheme().getSigningScheme() != SigningScheme.MANAGED) {
            requireNoSignatureFormattingConnector(w);
            requireNoLevelLadder(w);
            return;
        }
        requireStaticKeyManagedSigning(request.getSigningScheme());
        contentSigningWorkflowValidator
                .validate(w,
                        connectorService
                                .getConnectorEntityWithInterfaces(
                                        SecuredUUID.fromUUID(requireSignatureFormattingConnectorUuid(w))),
                        targetProfileUuid);
    }

    /**
     * Only the static-key scheme resolves for content signing, so a one-time-key profile would save cleanly and then
     * fail on every request.
     */
    private static void requireStaticKeyManagedSigning(SigningSchemeRequestDto scheme) {
        if (!(scheme instanceof StaticKeyManagedSigningRequestDto)) {
            throw new ValidationException("Managed content signing requires the %s managed signing type"
                    .formatted(ManagedSigningType.STATIC_KEY));
        }
    }

    private static UUID requireSignatureFormattingConnectorUuid(ContentSigningWorkflowRequestDto w) {
        if (w.getSignatureFormattingConnectorUuid() == null) {
            throw new ValidationException(
                    "Signature formatting connector is required for an ILM-managed content signing workflow");
        }
        return w.getSignatureFormattingConnectorUuid();
    }

    /**
     * Stamps the ladder columns a signing run reads to decide how high it may go. The workflow was already validated by
     * {@code validateContentSigningWorkflow} before the transaction opened; this only resolves and stores.
     */
    private void applyManagedContentSigning(SigningProfileVersion version, ContentSigningWorkflowRequestDto w)
            throws NotFoundException {
        Connector contentConnector = connectorService
                .getConnectorEntity(SecuredUUID.fromUUID(requireSignatureFormattingConnectorUuid(w)));
        version.setSignatureFormattingConnector(contentConnector);
        version.setSignatureFamily(w.getFamily());
        version.setMaxSignatureLevel(w.getMaxLevel());
        version.setTimestampSourceProfileUuid(TimestampSourceRequests.internalProfileUuid(w.getTimestampSource()));
        version.setRequireNonRepudiation(Boolean.TRUE.equals(w.getRequireNonRepudiation()));
        version.setRequiredExtendedKeyUsageOids(new ArrayList<>(safeOids(w)));
    }

    /**
     * A delegated signature is built by the signer connector outside ILM, which is why the API contract refuses a
     * formatting connector on such a request. A version that stored one anyway would advertise formatting the platform
     * never performs, and would collect attributes nothing ever replays.
     */
    private static void requireNoSignatureFormattingConnector(ContentSigningWorkflowRequestDto w) {
        if (w.getSignatureFormattingConnectorUuid() != null) {
            throw new ValidationException(
                    "signatureFormattingConnectorUuid must be omitted for delegated content signing: the signer connector builds the data to be signed itself");
        }
        if (w.getSignatureFormattingConnectorAttributes() != null
                && !w.getSignatureFormattingConnectorAttributes().isEmpty()) {
            throw new ValidationException(
                    "signatureFormattingConnectorAttributes must be omitted for delegated content signing: no formatting connector is configured to consume them");
        }
    }

    /**
     * A delegated signature is levelled entirely by the signer connector, so ILM configures no ladder for it. Ignoring
     * a ladder rather than refusing it would still let {@code maxLevel} decide which formatting operations' attributes
     * are collected and stored against a version whose ladder columns say those operations are out of scope.
     */
    private static void requireNoLevelLadder(ContentSigningWorkflowRequestDto w) {
        if (w.getFamily() != null || w.getMaxLevel() != null || w.getTimestampSource() != null) {
            throw new ValidationException(
                    "family, maxLevel and timestampSource must be omitted for delegated content signing: the signer connector levels the signature itself");
        }
    }

    private static Set<String> safeOids(ContentSigningWorkflowRequestDto w) {
        return w.getRequiredExtendedKeyUsageOids() == null ? Set.of() : w.getRequiredExtendedKeyUsageOids();
    }

    private static String notEligibleMessage(Certificate certificate, SigningWorkflowType workflowType,
            CertificatePurposeRequirements certificatePurpose) {
        return "Certificate " + certificate.getUuid() + " is not eligible for signing workflow type " + workflowType
                + CertificateEligibilityUtil
                        .describeSigningPurposeMismatch(certificate, workflowType, certificatePurpose)
                        .map(reason -> ": " + reason)
                        .orElse("");
    }

    private static CertificatePurposeRequirements certificatePurposeOf(SigningProfileVersion version) {
        return CertificatePurposeRequirements
                .of(version.isRequireNonRepudiation(), version.getRequiredExtendedKeyUsageOids());
    }

    private boolean recordPolicyDiffersFromVersion(SigningProfileVersion v, SigningRecordPolicyRequestDto p) {
        if (p == null) {
            return false;
        }
        return v.isRecordingEnabled() != p.isRecordingEnabled()
                || v.isRecordRequestMetadata() != p.isRecordRequestMetadata()
                || v.isRecordSignature() != p.isRecordSignature()
                || v.isRecordSignedDocument() != p.isRecordSignedDocument() || v.isRecordDtbs() != p.isRecordDtbs()
                || !Objects.equals(v.getRetentionDays(), p.getRetentionDays())
                || v.isDeleteAfterRetrieval() != p.isDeleteAfterRetrieval()
                || resolvePersistenceMode(p) != v.getPersistenceMode();
    }

    private void applyRecordPolicyToVersion(SigningProfileVersion v, SigningRecordPolicyRequestDto p) {
        if (p == null) {
            return;
        }
        v.setRecordingEnabled(p.isRecordingEnabled());
        v.setRecordRequestMetadata(p.isRecordRequestMetadata());
        v.setRecordSignature(p.isRecordSignature());
        v.setRecordSignedDocument(p.isRecordSignedDocument());
        v.setRecordDtbs(p.isRecordDtbs());
        v.setRetentionDays(p.getRetentionDays());
        v.setDeleteAfterRetrieval(p.isDeleteAfterRetrieval());
        v.setPersistenceMode(resolvePersistenceMode(p));
    }

    private SigningRecordPersistenceMode resolvePersistenceMode(SigningRecordPolicyRequestDto p) {
        return p.getPersistenceMode() != null ? p.getPersistenceMode() : SigningRecordPersistenceMode.DEFERRED_DURABLE;
    }

    /** A feature flag counts only on the interfaces it declares itself applicable to. */
    private void validateFormattingConnectorFeature(Connector connector, FeatureFlag requiredFeature,
            SigningWorkflowType workflowType) {
        List<ConnectorInterface> applicableInterfaces = requiredFeature.getApplicableInterfaces();
        boolean hasFeature = connector
                .getInterfaces()
                .stream()
                .filter(i -> applicableInterfaces.contains(i.getInterfaceCode()))
                .anyMatch(i -> i.getFeatures() != null && i.getFeatures().contains(requiredFeature));
        if (!hasFeature) {
            throw new ValidationException(
                    "Signature Formatting Provider '%s' does not support the '%s' feature required for %s workflow"
                            .formatted(connector.getName(), requiredFeature.getLabel(), workflowType.getLabel()));
        }
    }

    /**
     * Builds a full DTO from a version row. Reads attributes from AttributeEngine using the version number.
     */
    private SigningProfileDto buildDtoFromVersion(SigningProfile profile, SigningProfileVersion spv) {
        List<ResponseAttribute> customAttributes = attributeEngine
                .getObjectCustomAttributesContent(Resource.SIGNING_PROFILE, profile.getUuid());
        List<ResponseAttribute> signingOperationAttributes = attributeEngine
                .getObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .operation(AttributeOperation.SIGN)
                        .version(spv.getVersion())
                        .build());
        List<ResponseAttribute> signatureFormattingConnectorAttributes = attributeEngine
                .getObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.SIGNING_PROFILE, profile.getUuid())
                        .connector(spv.getSignatureFormattingConnectorUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTING)
                        .version(spv.getVersion())
                        .build());
        return SigningProfileMapper
                .toDto(profile, spv, customAttributes, signingOperationAttributes,
                        signatureFormattingConnectorAttributes, timestampSourceProfileName(spv));
    }

    private String timestampSourceProfileName(SigningProfileVersion version) {
        if (version.getTimestampSourceProfileUuid() == null) {
            return null;
        }
        return signingProfileRepository
                .findById(version.getTimestampSourceProfileUuid())
                .map(SigningProfile::getName)
                .orElse(null);
    }

    private SigningProfileDto buildDtoFromProfile(SigningProfile profile) {
        SigningProfileVersion current = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(profile.getUuid(), profile.getLatestVersion())
                .orElseThrow(() -> new IllegalStateException("No version row found for signing profile "
                        + profile.getUuid() + " version " + profile.getLatestVersion()));
        return buildDtoFromVersion(profile, current);
    }

    private List<ResponseAttribute> persistSigningOperationAttributes(SigningProfile signingProfile,
            SigningProfileVersion version, SigningSchemeRequestDto signingScheme)
            throws AttributeException, NotFoundException {
        if (signingScheme instanceof StaticKeyManagedSigningRequestDto staticKeyScheme) {
            List<RequestAttribute> signingOperationAttributes = staticKeyScheme.getSigningOperationAttributes();
            List<BaseAttribute> definitions = cryptographicKeyItemRepository
                    .findByKeyUuidIn(List.of(version.getCertificate().getKey().getUuid()))
                    .stream()
                    .findFirst()
                    .map(item -> cryptographicOperationService.listSignatureAttributes(item.getKeyAlgorithm()))
                    .orElse(List.of());

            // The signing operation attributes are Core-internal (not connector-owned), so connectorUuid is null.
            attributeEngine
                    .validateUpdateDataAttributes(null, AttributeOperation.SIGN, definitions,
                            signingOperationAttributes);
            return attributeEngine
                    .replaceObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, signingProfile.getUuid())
                            .operation(AttributeOperation.SIGN)
                            .version(version.getVersion())
                            .build(), signingOperationAttributes);
        }
        // For non-STATIC_KEY schemes, clean up any attributes that may remain for the current version.
        attributeEngine
                .deleteOperationObjectAttributesContent(AttributeType.DATA,
                        ObjectAttributeContentInfo
                                .builder(Resource.SIGNING_PROFILE, signingProfile.getUuid())
                                .operation(AttributeOperation.SIGN)
                                .version(version.getVersion())
                                .build());
        return List.of();
    }

    private List<ResponseAttribute> persistSignatureFormattingConnectorAttributes(SigningProfile p,
            SigningProfileVersion version, WorkflowRequestDto workflow, List<BaseAttribute> formattingDefinitions)
            throws AttributeException, NotFoundException {
        return switch (workflow) {
            case ContentSigningWorkflowRequestDto w -> {
                attributeEngine
                        .validateUpdateDataAttributes(w.getSignatureFormattingConnectorUuid(),
                                AttributeOperation.WORKFLOW_FORMATTING, formattingDefinitions,
                                w.getSignatureFormattingConnectorAttributes());
                yield attributeEngine
                        .replaceObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.SIGNING_PROFILE, p.getUuid())
                                .connector(w.getSignatureFormattingConnectorUuid())
                                .operation(AttributeOperation.WORKFLOW_FORMATTING)
                                .version(version.getVersion())
                                .build(), w.getSignatureFormattingConnectorAttributes());
            }
            case RawSigningWorkflowRequestDto ignored -> {
                // Raw signing has no formatting; clean up any formatting attributes that may remain for this version.
                attributeEngine
                        .deleteOperationObjectAttributesContent(AttributeType.DATA,
                                ObjectAttributeContentInfo
                                        .builder(Resource.SIGNING_PROFILE, p.getUuid())
                                        .operation(AttributeOperation.WORKFLOW_FORMATTING)
                                        .version(version.getVersion())
                                        .build());
                yield null;
            }
            case TimestampingWorkflowRequestDto w -> {
                attributeEngine
                        .validateUpdateDataAttributes(w.getSignatureFormattingConnectorUuid(),
                                AttributeOperation.WORKFLOW_FORMATTING, formattingDefinitions,
                                w.getSignatureFormattingConnectorAttributes());
                yield attributeEngine
                        .replaceObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.SIGNING_PROFILE, p.getUuid())
                                .connector(w.getSignatureFormattingConnectorUuid())
                                .operation(AttributeOperation.WORKFLOW_FORMATTING)
                                .version(version.getVersion())
                                .build(), w.getSignatureFormattingConnectorAttributes());
            }
            default -> throw new IllegalStateException("Unexpected type for Signing Workflow: " + workflow);
        };
    }

    /**
     * Fetches formatting attribute definitions from the connector without persisting them. Definitions are persisted
     * later inside the transaction by {@link #persistSignatureFormattingConnectorAttributes} via
     * {@link AttributeEngine#validateUpdateDataAttributes}, which keeps the definition upsert and content write atomic.
     */
    private List<BaseAttribute> fetchFormattingAttributeDefinitions(WorkflowRequestDto workflow)
            throws ConnectorException, NotFoundException {
        return switch (workflow) {
            case ContentSigningWorkflowRequestDto w -> w.getSignatureFormattingConnectorUuid() == null
                    ? List.of()
                    : contentSigningFormattingAttributes
                            .aggregate(
                                    connectorService.getConnectorForApiClient(w.getSignatureFormattingConnectorUuid()),
                                    w.getMaxLevel());
            case TimestampingWorkflowRequestDto w ->
                fetchFormattingAttributeDefinitions(w.getSignatureFormattingConnectorUuid());
            default -> List.of();
        };
    }

    private List<BaseAttribute> fetchFormattingAttributeDefinitions(UUID connectorUuid)
            throws ConnectorException, NotFoundException {
        ApiClientConnectorInfo apiClientInfo = connectorService.getConnectorForApiClient(connectorUuid);
        return connectorApiFactory
                .getSignatureFormattingApiClient(apiClientInfo)
                .listFormattingAttributes(apiClientInfo);
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
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
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

    private CommentInternalService commentService;

    @Autowired
    public void setCommentService(CommentInternalService commentService) {
        this.commentService = commentService;
    }

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
    public void setCryptographicOperationService(CryptographicOperationInternalService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setTokenProfileService(TokenProfileInternalService tokenProfileService) {
        this.tokenProfileService = tokenProfileService;
    }

    @Autowired
    public void setRaProfileService(RaProfileInternalService raProfileService) {
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
    public void setTimeQualityConfigurationRepository(
            TimeQualityConfigurationRepository timeQualityConfigurationRepository) {
        this.timeQualityConfigurationRepository = timeQualityConfigurationRepository;
    }

    @Autowired
    public void setSigningRecordService(SigningRecordExternalService signingRecordService) {
        this.signingRecordService = signingRecordService;
    }

    @Autowired
    public void setSigningRecordInternalService(SigningRecordInternalService signingRecordInternalService) {
        this.signingRecordInternalService = signingRecordInternalService;
    }

    @Autowired
    @Lazy
    public void setTspProfileService(TspProfileInternalService tspProfileService) {
        this.tspProfileService = tspProfileService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setClusterSynchronizer(ClusterOperationSynchronizer clusterSynchronizer) {
        this.clusterSynchronizer = clusterSynchronizer;
    }

    @Autowired
    public void setContentSigningWorkflowValidator(ContentSigningWorkflowValidator contentSigningWorkflowValidator) {
        this.contentSigningWorkflowValidator = contentSigningWorkflowValidator;
    }

    @Autowired
    public void setContentSigningFormattingAttributes(
            ContentSigningFormattingAttributes contentSigningFormattingAttributes) {
        this.contentSigningFormattingAttributes = contentSigningFormattingAttributes;
    }
}
