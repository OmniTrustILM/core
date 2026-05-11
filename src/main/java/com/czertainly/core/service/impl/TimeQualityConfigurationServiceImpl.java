package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Audited_;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration_;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.mapper.signing.TimeQualityConfigurationMapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TimeQualityConfigurationService;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.SearchHelper;
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

@Slf4j
@Service(Resource.Codes.TIME_QUALITY_CONFIGURATION)
public class TimeQualityConfigurationServiceImpl implements TimeQualityConfigurationService {

    private static final String NOT_FOUND_MSG = "Time Quality Configuration not found: ";

    private AttributeEngine attributeEngine;
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private TimeQualityConfigurationServiceImpl self;

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.TIME_QUALITY_CONFIGURATION, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.TIME_QUALITY_CONFIGURATION_NAME),
                SearchHelper.prepareSearch(FilterField.TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD),
                SearchHelper.prepareSearch(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE),
                SearchHelper.prepareSearch(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SAMPLES_PER_SERVER),
                SearchHelper.prepareSearch(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS, timeQualityConfigurationRepository.findAllNtpServers())
        ));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<TimeQualityConfigurationListDto> listTimeQualityConfigurations(SearchRequestDto request, SecurityFilter filter) {
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<TimeQualityConfiguration>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<TimeQualityConfigurationListDto> configurations = timeQualityConfigurationRepository.findUsingSecurityFilter(filter, List.of(), predicate, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream()
                .map(TimeQualityConfigurationMapper::toListDto)
                .toList();
        PaginationResponseDto<TimeQualityConfigurationListDto> response = new PaginationResponseDto<>();
        response.setItems(configurations);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        response.setTotalItems(timeQualityConfigurationRepository.countUsingSecurityFilter(filter, predicate));
        response.setTotalPages((int) Math.ceil((double) response.getTotalItems() / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public TimeQualityConfigurationDto getTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException {
        TimeQualityConfiguration configuration = timeQualityConfigurationRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NOT_FOUND_MSG + uuid));
        List<ResponseAttribute> customAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.TIME_QUALITY_CONFIGURATION, configuration.getUuid());
        return TimeQualityConfigurationMapper.toDto(configuration, customAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.CREATE)
    @Transactional
    public TimeQualityConfigurationDto createTimeQualityConfiguration(TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        if (timeQualityConfigurationRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException("Time Quality Configuration with name '" + request.getName() + "' already exists.");
        }
        attributeEngine.validateCustomAttributesContent(Resource.TIME_QUALITY_CONFIGURATION, request.getCustomAttributes());

        TimeQualityConfiguration configuration = new TimeQualityConfiguration();
        fillTimeQualityConfigurationEntity(configuration, request);
        TimeQualityConfiguration saved = saveOrTranslateUniqueViolation(configuration, request.getName());

        List<ResponseAttribute> customAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.TIME_QUALITY_CONFIGURATION, saved.getUuid(), request.getCustomAttributes());
        return TimeQualityConfigurationMapper.toDto(saved, customAttributes);

    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.UPDATE)
    @Transactional
    public TimeQualityConfigurationDto updateTimeQualityConfiguration(SecuredUUID uuid, TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfiguration configuration = timeQualityConfigurationRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NOT_FOUND_MSG + uuid));

        Optional<TimeQualityConfiguration> existingWithSameName = timeQualityConfigurationRepository.findByName(request.getName());
        if (existingWithSameName.isPresent() && !existingWithSameName.get().getUuid().equals(configuration.getUuid())) {
            throw new AlreadyExistException("Time Quality Configuration with name '" + request.getName() + "' already exists.");
        }
        attributeEngine.validateCustomAttributesContent(Resource.TIME_QUALITY_CONFIGURATION, request.getCustomAttributes());

        fillTimeQualityConfigurationEntity(configuration, request);
        TimeQualityConfiguration saved = saveOrTranslateUniqueViolation(configuration, request.getName());

        List<ResponseAttribute> customAttributes = attributeEngine.updateObjectCustomAttributesContent(Resource.TIME_QUALITY_CONFIGURATION, saved.getUuid(), request.getCustomAttributes());
        return TimeQualityConfigurationMapper.toDto(saved, customAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DELETE)
    @Transactional
    public void deleteTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException {
        deleteTimeQualityConfiguration(getTimeQualityConfigurationEntity(uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteTimeQualityConfigurations(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TimeQualityConfiguration configuration = null;
            try {
                configuration = getTimeQualityConfigurationEntity(uuid);
                self.deleteInOwnTransaction(configuration);
            } catch (Exception e) {
                log.error("Failed to delete Time Quality Configuration {}", uuid, e);
                messages.add(new BulkActionMessageDto(uuid.toString(), configuration != null ? configuration.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(TimeQualityConfiguration configuration) {
        deleteTimeQualityConfiguration(configuration);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ResourceExtensionService
    // ──────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return timeQualityConfigurationRepository.findResourceObject(objectUuid, TimeQualityConfiguration_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return timeQualityConfigurationRepository.findResourceObject(objectUuid.getValue(), TimeQualityConfiguration_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return timeQualityConfigurationRepository.listResourceObjects(filter, TimeQualityConfiguration_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TIME_QUALITY_CONFIGURATION, action = ResourceAction.UPDATE)
    @Transactional(readOnly = true)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        timeQualityConfigurationRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NOT_FOUND_MSG + uuid));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private TimeQualityConfiguration getTimeQualityConfigurationEntity(SecuredUUID uuid) throws NotFoundException {
        return timeQualityConfigurationRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NOT_FOUND_MSG + uuid));
    }

    private void fillTimeQualityConfigurationEntity(TimeQualityConfiguration entity, TimeQualityConfigurationRequestDto request) {
        entity.setName(request.getName());
        entity.setAccuracy(request.getAccuracy());
        entity.setNtpServers(request.getNtpServers());
        entity.setNtpCheckInterval(request.getNtpCheckInterval());
        entity.setNtpSamplesPerServer(request.getNtpSamplesPerServer());
        entity.setNtpCheckTimeout(request.getNtpCheckTimeout());
        entity.setNtpServersMinReachable(request.getNtpServersMinReachable());
        entity.setMaxClockDrift(request.getMaxClockDrift());
        entity.setLeapSecondGuard(request.isLeapSecondGuard());
    }

    private void deleteTimeQualityConfiguration(TimeQualityConfiguration configuration) {
        attributeEngine.deleteObjectAttributeContent(Resource.TIME_QUALITY_CONFIGURATION, configuration.getUuid());
        timeQualityConfigurationRepository.delete(configuration);
    }

    private TimeQualityConfiguration saveOrTranslateUniqueViolation(TimeQualityConfiguration configuration, String name) throws AlreadyExistException {
        try {
            return timeQualityConfigurationRepository.saveAndFlush(configuration);
        } catch (DataIntegrityViolationException e) {
            throw new AlreadyExistException("Time Quality Configuration with name '" + name + "' already exists.");
        }
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTimeQualityConfigurationRepository(TimeQualityConfigurationRepository timeQualityConfigurationRepository) {
        this.timeQualityConfigurationRepository = timeQualityConfigurationRepository;
    }

    @Lazy
    @Autowired
    public void setSelf(TimeQualityConfigurationServiceImpl self) {
        this.self = self;
    }
}
