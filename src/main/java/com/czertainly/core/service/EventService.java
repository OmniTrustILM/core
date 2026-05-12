package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.workflows.EventHistoryDto;
import com.czertainly.api.model.core.workflows.EventHistoryRequestDto;
import com.czertainly.api.model.core.workflows.ObjectEventHistoryDto;

import java.util.UUID;


public interface EventService {

    PaginationResponseDto<ObjectEventHistoryDto> getEventHistory(Resource resource, UUID uuid, PaginationRequestDto pagination) throws NotFoundException;

    PaginationResponseDto<EventHistoryDto> getEventHistory(ResourceEvent event, Resource resource, UUID uuid, EventHistoryRequestDto request) throws NotFoundException;

}
