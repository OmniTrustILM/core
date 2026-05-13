package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
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
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.mapper.signing.TspProfileMapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
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

@Service(Resource.Codes.TSP_PROFILE)
@Slf4j
public class TspProfileServiceImpl implements TspProfileService {
    private AttributeEngine attributeEngine;
    private TspProfileServiceImpl self;
    private TspProfileRepository tspProfileRepository;

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.TSP_PROFILE, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.TSP_PROFILE_NAME),
                SearchHelper.prepareSearch(FilterField.TSP_PROFILE_ENABLED)
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
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public TspProfileDto getTspProfile(SecuredUUID uuid) throws NotFoundException {
        TspProfile profile = getTspProfileEntity(uuid);
        List<ResponseAttribute> customAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.TSP_PROFILE, uuid.getValue());
        return TspProfileMapper.toDto(profile, customAttributes);
    }

    @Override
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
        validateCreateUpdateRequest(request);
        TspProfile profile = new TspProfile();
        return updateAndMapToDto(profile, request);
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

        validateCreateUpdateRequest(request);
        return updateAndMapToDto(profile, request);
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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Delete failed"));
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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Enable failed"));
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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), profile != null ? profile.getName() : "", e, "Disable failed"));
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

    private void validateCreateUpdateRequest(TspProfileRequestDto request) throws ValidationException {
        attributeEngine.validateCustomAttributesContent(Resource.TSP_PROFILE, request.getCustomAttributes());
    }

    private TspProfileDto updateAndMapToDto(TspProfile profile, TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
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
        attributeEngine.deleteObjectAttributeContent(Resource.TSP_PROFILE, profile.getUuid());
        tspProfileRepository.delete(profile);
    }

    private void enableTspProfile(TspProfile profile) {
        profile.setEnabled(true);
        tspProfileRepository.save(profile);
    }

    private void disableTspProfile(TspProfile profile) {
        profile.setEnabled(false);
        tspProfileRepository.save(profile);
    }

    private TspProfile getTspProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return tspProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("TSP Profile not found: " + uuid));
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTspProfileRepository(TspProfileRepository tspProfileRepository) {
        this.tspProfileRepository = tspProfileRepository;
    }

    @Lazy
    @Autowired
    public void setSelf(TspProfileServiceImpl self) {
        this.self = self;
    }
}
