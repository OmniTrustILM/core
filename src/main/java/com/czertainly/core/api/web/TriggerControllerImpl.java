package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.TriggerController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.TriggerExternalService;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
public class TriggerControllerImpl implements TriggerController {

    private TriggerExternalService triggerService;

    @Autowired
    public void setTriggerService(TriggerExternalService triggerService) {
        this.triggerService = triggerService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.LIST)
    public List<TriggerDto> listTriggers(Resource resource) {
        return triggerService.listTriggers(resource);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.CREATE)
    public TriggerDetailDto createTrigger(TriggerRequestDto request) throws NotFoundException, AlreadyExistException {
        return triggerService.createTrigger(request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.DETAIL)
    public TriggerDetailDto getTrigger(@LogResource(uuid = true) String triggerUuid) throws NotFoundException {
        return triggerService.getTrigger(triggerUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.UPDATE)
    public TriggerDetailDto updateTrigger(@LogResource(uuid = true) String triggerUuid, UpdateTriggerRequestDto request) throws NotFoundException {
        return triggerService.updateTrigger(triggerUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.DELETE)
    public void deleteTrigger(@LogResource(uuid = true) String triggerUuid) throws NotFoundException {
        triggerService.deleteTrigger(triggerUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.HISTORY)
    public List<TriggerHistoryDto> getTriggerHistory(@LogResource(uuid = true) String triggerUuid, String associationObjectUuid) {
        return triggerService.getTriggerHistory(triggerUuid, associationObjectUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.SUMMARY)
    public TriggerHistorySummaryDto getTriggerHistorySummary(String associationObjectUuid) throws NotFoundException {
        return triggerService.getTriggerHistorySummary(associationObjectUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.ASSOCIATE)
    public void associateEventTriggers(TriggerEventAssociationRequestDto request) throws NotFoundException {
        triggerService.createTriggerAssociations(request.getEvent(), request.getResource(), request.getObjectUuid(), request.getTriggerUuids(), true);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.TRIGGER, operation = Operation.LIST_ASSOCIATIONS)
    public Map<ResourceEvent, List<UUID>> getEventTriggersAssociations(Resource resource, UUID associationObjectUuid) {
        return triggerService.getTriggersAssociations(resource, associationObjectUuid);
    }
}
