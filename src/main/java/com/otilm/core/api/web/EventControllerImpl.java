package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.EventController;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.workflows.EventHistoryDto;
import com.otilm.api.model.core.workflows.EventHistoryRequestDto;
import com.otilm.api.model.core.workflows.ObjectEventHistoryDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.EventExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import com.otilm.core.util.converter.ResourceEventCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class EventControllerImpl implements EventController {

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
        webdataBinder.registerCustomEditor(ResourceEvent.class, new ResourceEventCodeConverter());
    }

    private EventExternalService eventService;

    @Autowired
    public void setEventService(EventExternalService eventService) {
        this.eventService = eventService;
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RESOURCE_EVENT, operation = Operation.HISTORY)
    public PaginationResponseDto<ObjectEventHistoryDto> getObjectEventHistory(@LogResource(affiliated = true) Resource resource, @LogResource(uuid = true, affiliated = true) UUID uuid, PaginationRequestDto pagination) throws NotFoundException {
        return eventService.getEventHistory(resource, uuid, pagination);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RESOURCE_EVENT, operation = Operation.HISTORY)
    public PaginationResponseDto<EventHistoryDto> getPlatformSettingsEventHistory(ResourceEvent event, EventHistoryRequestDto request) throws NotFoundException {
        return eventService.getEventHistory(event, null, null, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RESOURCE_EVENT, operation = Operation.HISTORY)
    public PaginationResponseDto<EventHistoryDto> getObjectDefinedEventHistory(ResourceEvent event, @LogResource(affiliated = true) Resource resource, @LogResource(affiliated = true, uuid = true) UUID uuid, EventHistoryRequestDto request) throws NotFoundException {
        return eventService.getEventHistory(event, resource, uuid, request);
    }
}
