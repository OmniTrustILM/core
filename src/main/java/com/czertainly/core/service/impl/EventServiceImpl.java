package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.other.ResourceObjectDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.workflows.EventHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerHistoryRepository;
import com.czertainly.core.mapper.workflows.EventHistoryMapper;
import com.czertainly.core.mapper.workflows.PaginationResponseMapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.service.EventExternalService;
import com.czertainly.core.service.ResourceService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class EventServiceImpl implements EventExternalService {

    private ResourceService resourceService;

    private TriggerHistoryRepository triggerHistoryRepository;
    private EventHistoryRepository eventHistoryRepository;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setTriggerHistoryRepository(TriggerHistoryRepository triggerHistoryRepository) {
        this.triggerHistoryRepository = triggerHistoryRepository;
    }

    @Autowired
    public void setEventHistoryRepository(EventHistoryRepository eventHistoryRepository) {
        this.eventHistoryRepository = eventHistoryRepository;
    }


    @Override
    @Transactional
    @ExternalAuthorization(resource = Resource.RESOURCE_EVENT, action = ResourceAction.DETAIL)
    public PaginationResponseDto<ObjectEventHistoryDto> getEventHistory(Resource resource, UUID uuid, PaginationRequestDto pagination) throws NotFoundException {
        // Check if object is present for the given resource and uuid and if user has permissions for details of the object
        resourceService.getResourceObject(resource, uuid);
        Page<TriggerHistory> triggerHistoryPage = triggerHistoryRepository.findByObjectUuidAndObjectResourceOrderByTriggeredAtDesc(uuid, resource, PageRequest.of(pagination.getPageNumber() - 1, pagination.getItemsPerPage()));
        List<ObjectEventHistoryDto> eventHistoryDtos = triggerHistoryPage.get().map(
                triggerHistory -> {
                    ResourceObjectDto resourceObjectDto = getOriginResourceObjectDto(triggerHistory);
                    return EventHistoryMapper.toObjectEventHistoryDto(triggerHistory, resourceObjectDto);
                }
        ).toList();
        return PaginationResponseMapper.toDto(triggerHistoryPage, eventHistoryDtos);
    }

    private ResourceObjectDto getOriginResourceObjectDto(TriggerHistory triggerHistory) {
        ResourceObjectDto resourceObjectDto = new ResourceObjectDto();
        if (triggerHistory.getTriggerAssociation() != null)  {
            if (triggerHistory.getTriggerAssociation().getResource() == null) {
                resourceObjectDto.setResource(Resource.SETTINGS);
            }
            else {
                try {
                    resourceObjectDto = resourceService.getResourceObject(triggerHistory.getTriggerAssociation().getResource(), triggerHistory.getTriggerAssociation().getObjectUuid());
                } catch (NotFoundException e) {
                    resourceObjectDto.setResource(triggerHistory.getTriggerAssociation().getResource());
                }
            }
        }
        return resourceObjectDto;
    }

    @Override
    @Transactional
    @ExternalAuthorization(resource = Resource.RESOURCE_EVENT, action = ResourceAction.DETAIL)
    public PaginationResponseDto<EventHistoryDto> getEventHistory(ResourceEvent event, Resource resource, UUID uuid, EventHistoryRequestDto request) throws NotFoundException {
        if (uuid == null && resource != null || uuid != null && resource == null) {
            throw new ValidationException("Missing UUID or Resource");
        }
        if (uuid != null) {
            // Check if object is present for the given resource and uuid and if user has permissions for details of the object
            resourceService.getResourceObject(resource, uuid);
        }

        Page<EventHistory> eventHistories = eventHistoryRepository.findByEventAndResourceAndResourceUuidOrderByStartedAtDesc(event, resource, uuid, PageRequest.of(request.getPagination().getPageNumber() - 1, request.getPagination().getItemsPerPage()));
        if (eventHistories.isEmpty()) {
            return PaginationResponseMapper.toDto(eventHistories, List.of());
        }

        List<UUID> eventHistoryUuids = eventHistories.stream().map(EventHistory::getUuid).toList();

        // Batch 1: all three counts in one GROUP BY query (replaces 3 per-row count queries)
        Map<UUID, int[]> countsPerEvent = triggerHistoryRepository.countStatsByEventHistoryUuids(eventHistoryUuids)
                .stream().collect(Collectors.toMap(
                        row -> (UUID) row[0],
                        row -> new int[]{
                                ((Number) row[1]).intValue(),
                                ((Number) row[2]).intValue(),
                                ((Number) row[3]).intValue()
                        }
                ));

        // Batch 2: paginated object UUIDs for all event histories in one window-function query
        int objectsPageNumber = request.getObjectsPagination().getPageNumber();
        int objectsItemsPerPage = request.getObjectsPagination().getItemsPerPage();
        int offset = (objectsPageNumber - 1) * objectsItemsPerPage;
        Map<UUID, List<UUID>> paginatedObjectUuidsPerEvent = triggerHistoryRepository
                .findPaginatedObjectUuidsByEventHistoryUuids(eventHistoryUuids, offset, objectsItemsPerPage)
                .stream().collect(Collectors.groupingBy(
                        row -> (UUID) row[0],
                        LinkedHashMap::new,
                        Collectors.mapping(row -> (UUID) row[1], Collectors.toList())
                ));

        // Batch 3: all trigger histories for the paginated object UUIDs in one query, then group in Java.
        // Null object_uuid (ignored certificates) is a valid paginated entry; filter it from the IN parameter
        // since OR t.objectUuid IS NULL in the query handles that clause. Hibernate renders an empty IN as (1=0),
        // so the OR branch still fires when the page contains only null entries.
        List<UUID> allPaginatedObjectUuids = paginatedObjectUuidsPerEvent.values().stream()
                .flatMap(Collection::stream).filter(Objects::nonNull).distinct().toList();
        boolean hasNullObjectUuid = paginatedObjectUuidsPerEvent.values().stream().anyMatch(list -> list.contains(null));
        Map<UUID, Map<UUID, List<TriggerHistory>>> triggerHistoriesByEventAndObject = new LinkedHashMap<>();
        if (!allPaginatedObjectUuids.isEmpty() || hasNullObjectUuid) {
            for (TriggerHistory th : triggerHistoryRepository.findByEventHistoryUuidsAndObjectUuids(eventHistoryUuids, allPaginatedObjectUuids)) {
                triggerHistoriesByEventAndObject
                        .computeIfAbsent(th.getEventHistoryUuid(), k -> new LinkedHashMap<>())
                        .computeIfAbsent(th.getObjectUuid(), k -> new ArrayList<>())
                        .add(th);
            }
        }

        List<EventHistoryDto> eventHistoriesResponse = eventHistories.stream()
                .map(eventHistory -> {
                    int[] counts = countsPerEvent.getOrDefault(eventHistory.getUuid(), new int[]{0, 0, 0});
                    List<UUID> paginatedObjectUuids = paginatedObjectUuidsPerEvent.getOrDefault(eventHistory.getUuid(), List.of());
                    Map<UUID, List<TriggerHistory>> triggerHistoriesPerObject = triggerHistoriesByEventAndObject.getOrDefault(eventHistory.getUuid(), Map.of());
                    return EventHistoryMapper.toEventHistoryDto(
                            eventHistory,
                            counts[0], counts[1], counts[2],
                            paginatedObjectUuids, objectsPageNumber, objectsItemsPerPage,
                            triggerHistoriesPerObject
                    );
                }).toList();

        return PaginationResponseMapper.toDto(eventHistories, eventHistoriesResponse);
    }

}
