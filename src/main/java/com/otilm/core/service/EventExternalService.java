package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.workflows.EventHistoryDto;
import com.otilm.api.model.core.workflows.EventHistoryRequestDto;
import com.otilm.api.model.core.workflows.ObjectEventHistoryDto;

import java.util.UUID;

public interface EventExternalService {

    PaginationResponseDto<ObjectEventHistoryDto> getEventHistory(Resource resource, UUID uuid, PaginationRequestDto pagination) throws NotFoundException;

    PaginationResponseDto<EventHistoryDto> getEventHistory(ResourceEvent event, Resource resource, UUID uuid, EventHistoryRequestDto request) throws NotFoundException;
}
