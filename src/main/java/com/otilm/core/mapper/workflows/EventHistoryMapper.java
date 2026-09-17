package com.otilm.core.mapper.workflows;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.api.model.core.workflows.EventHistoryDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.ObjectEventHistoryDto;
import com.otilm.api.model.core.workflows.TriggerHistoryObjectSummaryDto;
import com.otilm.api.model.core.workflows.TriggerHistoryObjectTriggerSummaryDto;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.entity.workflows.TriggerHistoryRecord;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

public class EventHistoryMapper {

    private EventHistoryMapper() {
    }

    public static ObjectEventHistoryDto toObjectEventHistoryDto(TriggerHistory triggerHistory,
            ResourceObjectDto origin) {
        ObjectEventHistoryDto dto = new ObjectEventHistoryDto();
        dto.setEvent(triggerHistory.getEvent());
        dto.setOrigin(origin);
        if (triggerHistory.getTrigger() != null) {
            dto.setTrigger(new NameAndUuidDto(triggerHistory.getTriggerUuid(), triggerHistory.getTrigger().getName()));
        }
        dto.setConditionsMatched(triggerHistory.isConditionsMatched());
        dto.setActionsPerformed(triggerHistory.isActionsPerformed());
        dto.setTriggeredAt(triggerHistory.getTriggeredAt());
        dto.setMessage(triggerHistory.getMessage());
        dto.setRecords(triggerHistory.getRecords().stream().map(TriggerHistoryRecord::mapToDto).toList());
        dto.setNotificationsSent(notificationsSent(triggerHistory));
        return dto;
    }

    public static TriggerHistoryObjectTriggerSummaryDto toTriggerHistoryObjectTriggerSummaryDto(
            TriggerHistory triggerHistory) {
        TriggerHistoryObjectTriggerSummaryDto triggerHistoryDto = new TriggerHistoryObjectTriggerSummaryDto();
        triggerHistoryDto.setMessage(triggerHistory.getMessage());
        triggerHistoryDto
                .setTriggerName(triggerHistory.getTrigger() != null ? triggerHistory.getTrigger().getName() : null);
        triggerHistoryDto.setTriggerUuid(triggerHistory.getTriggerUuid());
        triggerHistoryDto.setTriggeredAt(triggerHistory.getTriggeredAt());
        triggerHistoryDto.setRecords(triggerHistory.getRecords().stream().map(TriggerHistoryRecord::mapToDto).toList());
        triggerHistoryDto.setNotificationsSent(notificationsSent(triggerHistory));
        return triggerHistoryDto;
    }

    public static TriggerHistoryObjectSummaryDto toTriggerHistoryObjectSummaryDto(List<TriggerHistory> triggerHistories,
            UUID objectUuid, ResourceObjectDto hostObject) {
        TriggerHistoryObjectSummaryDto triggerHistoryObjectSummaryDto = new TriggerHistoryObjectSummaryDto();
        triggerHistoryObjectSummaryDto.setObjectUuid(objectUuid);
        triggerHistoryObjectSummaryDto.setHostObject(hostObject);
        boolean ignored = triggerHistories
                .stream()
                .filter(th -> th.getTrigger().isIgnoreTrigger())
                .anyMatch(TriggerHistory::isActionsPerformed);
        triggerHistoryObjectSummaryDto.setIgnored(ignored);
        triggerHistoryObjectSummaryDto
                .setMatched(ignored || triggerHistories
                        .stream()
                        .filter(th -> !th.getTrigger().isIgnoreTrigger())
                        .anyMatch(TriggerHistory::isConditionsMatched));
        triggerHistoryObjectSummaryDto
                .setTriggers(triggerHistories
                        .stream()
                        .map(EventHistoryMapper::toTriggerHistoryObjectTriggerSummaryDto)
                        .toList());
        return triggerHistoryObjectSummaryDto;
    }

    public static EventHistoryDto toEventHistoryDto(EventHistory eventHistory, int objectsEvaluated, int objectsMatched,
            int objectsIgnored, List<UUID> paginatedObjectUuids, int objectsPageNumber, int objectsItemsPerPage,
            Map<UUID, List<TriggerHistory>> triggerHistoriesPerObject, Map<UUID, ResourceObjectDto> hostObjects) {
        EventHistoryDto dto = new EventHistoryDto();
        dto.setResource(eventHistory.getEvent().getResource());
        dto.setStartedAt(eventHistory.getStartedAt());
        dto.setFinishedAt(eventHistory.getFinishedAt());
        dto.setStatus(eventHistory.getStatus());
        dto.setObjectsEvaluated(objectsEvaluated);
        dto.setObjectsMatched(objectsMatched);
        dto.setObjectsIgnored(objectsIgnored);
        List<TriggerHistoryObjectSummaryDto> triggerHistoriesInEvent = paginatedObjectUuids
                .stream()
                .map(objectUuid -> EventHistoryMapper
                        .toTriggerHistoryObjectSummaryDto(triggerHistoriesPerObject.getOrDefault(objectUuid, List.of()),
                                objectUuid, objectUuid == null ? null : hostObjects.get(objectUuid)))
                .toList();

        dto
                .setObjectHistories(PaginationResponseMapper
                        .toDto(triggerHistoriesInEvent, objectsPageNumber, objectsItemsPerPage, objectsEvaluated));
        return dto;
    }

    @Nullable
    private static Boolean notificationsSent(TriggerHistory triggerHistory) {
        // If there was any action sending notifications and conditions were met and there is no trigger history record
        // for failed execution with send notification type
        boolean notificationsInTrigger = triggerHistory.getTrigger() != null && triggerHistory
                .getTrigger()
                .getActions()
                .stream()
                .anyMatch(action -> action
                        .getExecutions()
                        .stream()
                        .anyMatch(e -> e.getType() == ExecutionType.SEND_NOTIFICATION));
        if (notificationsInTrigger) {
            return triggerHistory.isConditionsMatched() && triggerHistory
                    .getRecords()
                    .stream()
                    .noneMatch(r -> r.getExecution() != null
                            && r.getExecution().getType() == ExecutionType.SEND_NOTIFICATION);
        }
        return null;
    }
}
