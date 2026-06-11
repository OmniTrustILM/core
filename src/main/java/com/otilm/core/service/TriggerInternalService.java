package com.otilm.core.service;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.entity.workflows.TriggerHistoryRecord;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface TriggerInternalService {

    Map<ResourceEvent, List<UUID>> getTriggersAssociations(Resource resource, UUID associationObjectUuid);

    void deleteTriggerAssociations(Resource resource, UUID associationObjectUuid);

    TriggerHistory createTriggerHistory(UUID triggerUuid, TriggerAssociation triggerAssociation, UUID objectUuid, UUID referenceObjectUuid, EventHistory eventHistory, Resource objectResource);
    TriggerHistoryRecord createTriggerHistoryRecord(UUID triggerHistoryUuid, UUID conditionUuid, UUID executionUuid, String message);

    void setTriggerHistoryActionsPerformedFalse(UUID triggerHistoryUuid);
}
