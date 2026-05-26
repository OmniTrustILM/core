package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface TriggerExternalService {

    List<TriggerDto> listTriggers(Resource resource);
    TriggerDetailDto getTrigger(String triggerUuid) throws NotFoundException;
    TriggerDetailDto createTrigger(TriggerRequestDto request) throws AlreadyExistException, NotFoundException;
    TriggerDetailDto updateTrigger(String triggerUuid, UpdateTriggerRequestDto request) throws NotFoundException, AlreadyExistException;
    void deleteTrigger(String triggerUuid) throws NotFoundException;

    Map<ResourceEvent, List<UUID>> getTriggersAssociations(Resource resource, UUID associationObjectUuid);
    void createTriggerAssociations(ResourceEvent event, Resource resource, UUID associationObjectUuid, List<UUID> triggerUuids, boolean replace) throws NotFoundException;

    List<TriggerHistoryDto> getTriggerHistory(String triggerUuid, String associationObjectUuid);
    TriggerHistorySummaryDto getTriggerHistorySummary(String associationObjectUuid) throws NotFoundException;
}
