package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Audited_;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.entity.signing.TspProfile_;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.mapper.signing.TspProfileMapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.service.SigningProfileService;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.config.CacheConfig;
import com.czertainly.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.TSP_PROFILE)
@Slf4j
public class TspProfileServiceImpl implements TspProfileService {
    private CacheManager cacheManager;
    private AttributeEngine attributeEngine;
    private TspProfileServiceImpl self;
    private SigningProfileRepository signingProfileRepository;
    private SigningProfileService signingProfileService;
    private TspProfileRepository tspProfileRepository;

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.TSP_PROFILE, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.TSP_PROFILE_NAME),
                SearchHelper.prepareSearch(FilterField.TSP_PROFILE_ENABLED),
                SearchHelper.prepareSearch(FilterField.TSP_PROFILE_DEFAULT_SIGNING_PROFILE, signingProfileRepository.findAllNames())
        ));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<TspProfileListDto> listTspProfiles(SearchRequestDto request, SecurityFilter filter) {
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<TspProfile>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<TspProfileListDto> profiles = tspProfileRepository.findUsingSecurityFilter(filter, List.of(), predicate, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream()
                .map(TspProfileMapper::toListDto)
                .toList();
        PaginationResponseDto<TspProfileListDto> response = new PaginationResponseDto<>();
        response.setItems(profiles);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        response.setTotalItems(tspProfileRepository.countUsingSecurityFilter(filter, predicate));
        response.setTotalPages((int) Math.ceil((double) response.getTotalItems() / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.LIST, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SecuredList<TspProfile> listTspProfilesUsingSigningProfileAsDefault(SecuredUUID signingProfileUuid, SecurityFilter filter) {
        List<TspProfile> tspProfiles = tspProfileRepository.findAllByDefaultSigningProfileUuid(signingProfileUuid.getValue());
        return SecuredList.fromFilter(filter, tspProfiles);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public TspProfileDto getTspProfile(SecuredUUID uuid) throws NotFoundException {
        TspProfile profile = getTspProfileEntity(uuid);
        List<ResponseAttribute> customAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.TSP_PROFILE, uuid.getValue());
        return TspProfileMapper.toDto(profile, customAttributes);
    }

    @Override
    @Cacheable(value = CacheConfig.TSP_PROFILES_CACHE, key = "#name")
    @Transactional(readOnly = true)
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL)
    public TspProfileModel getTspProfile(String name) throws NotFoundException {
        TspProfile tspConfiguration = tspProfileRepository.findWithAssociationsByName(name)
                .orElseThrow(() -> new NotFoundException("TSP Profile not found: " + name));

        List<ResponseAttribute> customAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.TSP_PROFILE, tspConfiguration.getUuid());
        return TspProfileMapper.toModel(tspConfiguration, customAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.CREATE)
    @Transactional
    public TspProfileDto createTspProfile(TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        if (tspProfileRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException("TSP Profile with name '" + request.getName() + "' already exists.");
        }
        SigningProfile defaultSigningProfile = validateCreateUpdateRequest(request);
        TspProfile profile = new TspProfile();
        return updateAndMapToDto(profile, request, defaultSigningProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.UPDATE)
    @Transactional
    public TspProfileDto updateTspProfile(SecuredUUID uuid, TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        TspProfile profile = getTspProfileEntity(uuid);

        Optional<TspProfile> existingWithSameName = tspProfileRepository.findByName(request.getName());
        if (existingWithSameName.isPresent() && !existingWithSameName.get().getUuid().equals(profile.getUuid())) {
            throw new AlreadyExistException("TSP Profile with name '" + request.getName() + "' already exists.");
        }

        String oldName = profile.getName();
        SigningProfile defaultSigningProfile = validateCreateUpdateRequest(request);
        TspProfileDto result = updateAndMapToDto(profile, request, defaultSigningProfile);
        evictTspProfileCache(oldName);
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DELETE)
    @Transactional
    public void deleteTspProfile(SecuredUUID uuid) throws NotFoundException {
        deleteTspProfile(getTspProfileEntity(uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteTspProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TspProfile profile = null;
            try {
                profile = getTspProfileEntity(uuid);
                self.deleteInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to delete TSP Profile {}", uuid, e);
                messages.add(new BulkActionMessageDto(uuid.toString(), profile != null ? profile.getName() : "", safeBulkMessage(e)));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(TspProfile profile) {
        deleteTspProfile(profile);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Enable / disable
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.ENABLE)
    @Transactional
    public void enableTspProfile(SecuredUUID uuid) throws NotFoundException {
        TspProfile profile = getTspProfileEntity(uuid);
        enableTspProfile(profile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.ENABLE)
    public List<BulkActionMessageDto> bulkEnableTspProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TspProfile profile = null;
            try {
                profile = getTspProfileEntity(uuid);
                self.enableInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to enable TSP Profile {}", uuid, e);
                messages.add(new BulkActionMessageDto(uuid.toString(), profile != null ? profile.getName() : "", safeBulkMessage(e)));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.ENABLE)
    @Transactional
    public void disableTspProfile(SecuredUUID uuid) throws NotFoundException {
        TspProfile profile = getTspProfileEntity(uuid);
        disableTspProfile(profile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.ENABLE)
    public List<BulkActionMessageDto> bulkDisableTspProfiles(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TspProfile profile = null;
            try {
                profile = getTspProfileEntity(uuid);
                self.disableInOwnTransaction(profile);
            } catch (Exception e) {
                log.error("Failed to disable TSP Profile {}", uuid, e);
                messages.add(new BulkActionMessageDto(uuid.toString(), profile != null ? profile.getName() : "", safeBulkMessage(e)));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void enableInOwnTransaction(TspProfile profile) {
        enableTspProfile(profile);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void disableInOwnTransaction(TspProfile profile) {
        disableTspProfile(profile);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ResourceExtensionService
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return tspProfileRepository.findResourceObject(objectUuid, TspProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return tspProfileRepository.findResourceObject(objectUuid.getValue(), TspProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return tspProfileRepository.listResourceObjects(filter, TspProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.UPDATE)
    @Transactional(readOnly = true)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getTspProfileEntity(uuid);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private static String safeBulkMessage(Exception e) {
        return e.getClass().getPackageName().startsWith("com.czertainly.api.exception") && e.getMessage() != null
                ? e.getMessage()
                : "Operation failed";
    }

    private SigningProfile validateCreateUpdateRequest(TspProfileRequestDto request) throws NotFoundException, ValidationException {
        attributeEngine.validateCustomAttributesContent(Resource.TSP_PROFILE, request.getCustomAttributes());

        SigningProfile defaultSigningProfile = null;
        if (request.getDefaultSigningProfileUuid() != null) {
            UUID defaultSigningProfileUuid = request.getDefaultSigningProfileUuid();
            defaultSigningProfile = signingProfileRepository.findByUuid(SecuredUUID.fromUUID(defaultSigningProfileUuid))
                    .orElseThrow(() -> new NotFoundException("Signing Profile not found: " + defaultSigningProfileUuid));
        }

        return defaultSigningProfile;
    }

    private TspProfileDto updateAndMapToDto(TspProfile profile, TspProfileRequestDto request, SigningProfile defaultSigningProfile) throws AlreadyExistException, AttributeException, NotFoundException {
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
        profile.setDefaultSigningProfile(defaultSigningProfile);
        TspProfile saved;
        try {
            saved = tspProfileRepository.saveAndFlush(profile);
        } catch (DataIntegrityViolationException e) {
            throw new AlreadyExistException("TSP Profile with name '" + request.getName() + "' already exists.");
        }

        List<ResponseAttribute> customAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.TSP_PROFILE, saved.getUuid(), request.getCustomAttributes());
        return TspProfileMapper.toDto(saved, customAttributes);

    }

    private void deleteTspProfile(TspProfile profile) {
        SecuredList<SigningProfile> signingProfiles = signingProfileService.listSigningProfilesAssociatedWithTsp(SecuredUUID.fromUUID(profile.getUuid()), SecurityFilter.create());
        if (!signingProfiles.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create(String.format(
                                    "Cannot delete TSP Profile: associated with Signing Profiles (%d): %s",
                                    signingProfiles.size(),
                                    signingProfiles.getAllowed().stream().map(SigningProfile::getName).collect(Collectors.joining(","))
                            )
                    )
            );
        }

        attributeEngine.deleteObjectAttributeContent(Resource.TSP_PROFILE, profile.getUuid());
        tspProfileRepository.delete(profile);
        evictTspProfileCache(profile.getName());
    }

    private void enableTspProfile(TspProfile profile) {
        profile.setEnabled(true);
        tspProfileRepository.save(profile);
        evictTspProfileCache(profile.getName());
    }

    private void disableTspProfile(TspProfile profile) {
        profile.setEnabled(false);
        tspProfileRepository.save(profile);
        evictTspProfileCache(profile.getName());
    }

    private TspProfile getTspProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return tspProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("TSP Profile not found: " + uuid));
    }

    private void evictTspProfileCache(String name) {
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILES_CACHE);
        if (cache != null) {
            cache.evict(name);
            log.debug("Evicted TSP profile cache entry for name '{}'", name);
        }
    }

    @Autowired
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTspProfileRepository(TspProfileRepository tspProfileRepository) {
        this.tspProfileRepository = tspProfileRepository;
    }

    @Autowired
    public void setSigningProfileRepository(SigningProfileRepository signingProfileRepository) {
        this.signingProfileRepository = signingProfileRepository;
    }

    @Autowired
    public void setSigningProfileService(SigningProfileService signingProfileService) {
        this.signingProfileService = signingProfileService;
    }

    @Lazy
    @Autowired
    public void setSelf(TspProfileServiceImpl self) {
        this.self = self;
    }
}
