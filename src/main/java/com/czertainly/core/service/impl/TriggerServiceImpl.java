package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.workflows.*;
import com.czertainly.core.dao.repository.workflows.*;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.TriggerService;
import com.czertainly.core.util.AuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class TriggerServiceImpl implements TriggerService {

    private static final Logger logger = LoggerFactory.getLogger(TriggerServiceImpl.class);

    private RuleRepository ruleRepository;

    private ActionRepository actionRepository;

    private TriggerRepository triggerRepository;

    private TriggerAssociationRepository triggerAssociationRepository;

    private TriggerHistoryRepository triggerHistoryRepository;

    private TriggerHistoryRecordRepository triggerHistoryRecordRepository;

    @Autowired
    public void setRuleRepository(RuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @Autowired
    public void setActionRepository(ActionRepository actionRepository) {
        this.actionRepository = actionRepository;
    }

    @Autowired
    public void setTriggerRepository(TriggerRepository triggerRepository) {
        this.triggerRepository = triggerRepository;
    }

    @Autowired
    public void setTriggerAssociationRepository(TriggerAssociationRepository triggerAssociationRepository) {
        this.triggerAssociationRepository = triggerAssociationRepository;
    }

    @Autowired
    public void setTriggerHistoryRepository(TriggerHistoryRepository triggerHistoryRepository) {
        this.triggerHistoryRepository = triggerHistoryRepository;
    }

    @Autowired
    public void setTriggerHistoryRecordRepository(TriggerHistoryRecordRepository triggerHistoryRecordRepository) {
        this.triggerHistoryRecordRepository = triggerHistoryRecordRepository;
    }

    //region Triggers

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.LIST)
    public List<TriggerDto> listTriggers(Resource resource) {
        List<Trigger> triggers;
        if (resource != null) {
            triggers = triggerRepository.findAllByResource(resource);
        } else {
            triggers = triggerRepository.findAll();
        }

        return triggers.stream().map(Trigger::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.DETAIL)
    public TriggerDetailDto getTrigger(String triggerUuid) throws NotFoundException {
        return triggerRepository.findByUuid(SecuredUUID.fromString(triggerUuid)).orElseThrow(() -> new NotFoundException(Trigger.class, triggerUuid)).mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.DETAIL)
    public Trigger getTriggerEntity(String triggerUuid) throws NotFoundException {
        return triggerRepository.findByUuid(SecuredUUID.fromString(triggerUuid)).orElseThrow(() -> new NotFoundException(Trigger.class, triggerUuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.CREATE)
    public TriggerDetailDto createTrigger(TriggerRequestDto request) throws AlreadyExistException, NotFoundException {
        if (request.getName() == null) {
            throw new ValidationException("Property name cannot be empty.");
        }
        validateTriggerRequest(request.getType(), request.getEvent(), request.isIgnoreTrigger(), request.getResource(), request.getActionsUuids());

        if (triggerRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("Trigger with same name already exists.");
        }

        Trigger trigger = new Trigger();

        trigger.setName(request.getName());
        trigger.setDescription(request.getDescription());
        trigger.setType(request.getType());
        trigger.setResource(request.getResource());
        trigger.setIgnoreTrigger(request.isIgnoreTrigger());
        trigger.setEvent(request.getEvent());
        triggerRepository.save(trigger);

        setTriggerRulesAndActions(trigger, request.getRulesUuids(), request.getActionsUuids());

        return trigger.mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.UPDATE)
    public TriggerDetailDto updateTrigger(String triggerUuid, UpdateTriggerRequestDto request) throws NotFoundException {
        validateTriggerRequest(request.getType(), request.getEvent(), request.isIgnoreTrigger(), request.getResource(), request.getActionsUuids());

        Trigger trigger = triggerRepository.findByUuid(SecuredUUID.fromString(triggerUuid)).orElseThrow(() -> new NotFoundException(Trigger.class, triggerUuid));

        trigger.setDescription(request.getDescription());
        trigger.setType(request.getType());
        trigger.setResource(request.getResource());
        trigger.setIgnoreTrigger(request.isIgnoreTrigger());
        trigger.setEvent(request.getEvent());

        setTriggerRulesAndActions(trigger, request.getRulesUuids(), request.getActionsUuids());

        triggerRepository.save(trigger);
        return trigger.mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.DELETE)
    public void deleteTrigger(String triggerUuid) throws NotFoundException {
        Trigger trigger = triggerRepository.findByUuid(SecuredUUID.fromString(triggerUuid)).orElseThrow(() -> new NotFoundException(Trigger.class, triggerUuid));

        List<TriggerAssociation> triggerAssociations = triggerAssociationRepository.findByTriggerUuid(trigger.getUuid());
        if (!triggerAssociations.isEmpty()) {
            throw new ValidationException("Cannot delete trigger. It has %d event association(s): %s".formatted(triggerAssociations.size(), triggerAssociations.stream().map(a -> "%s (%s%s)".formatted(a.getEvent().getLabel(), a.getResource() == null ? Resource.SETTINGS.getLabel() : a.getResource().getLabel(), a.getObjectUuid() == null ? "" : " " + a.getObjectUuid())).collect(Collectors.joining(", "))));
        }

        triggerAssociationRepository.deleteByTriggerUuid(trigger.getUuid());
        triggerRepository.delete(trigger);
    }

    private void setTriggerRulesAndActions(Trigger trigger, List<String> rulesUuids, List<String> actionsUuids) throws NotFoundException {
        Set<Rule> rules = new HashSet<>();
        for (String ruleUuid : rulesUuids) {
            Rule rule = ruleRepository.findWithConditionsByUuid(UUID.fromString(ruleUuid)).orElseThrow(() -> new NotFoundException(Rule.class, ruleUuid));
            if (rule.getResource() != Resource.ANY && rule.getResource() != trigger.getResource()) {
                throw new ValidationException("Resource of rule '%s' does not match trigger resource.".formatted(rule.getName()));
            }
            for (Condition condition : rule.getConditions()) {
                if (condition.getResource() != Resource.ANY && condition.getResource() != trigger.getResource()) {
                    throw new ValidationException("Resource of condition '%s' of rule '%s' does not match trigger resource.".formatted(condition.getName(), rule.getName()));
                }
            }
            rules.add(rule);
        }

        Set<Action> actions = new HashSet<>();
        for (String actionUuid : actionsUuids) {
            Action action = actionRepository.findWithExecutionsByUuid(UUID.fromString(actionUuid)).orElseThrow(() -> new NotFoundException(Action.class, actionUuid));
            if (action.getResource() != Resource.ANY && action.getResource() != trigger.getResource()) {
                throw new ValidationException("Resource of action '%s' does not match trigger resource.".formatted(action.getName()));
            }
            for (Execution execution : action.getExecutions()) {
                if (execution.getResource() != Resource.ANY && execution.getResource() != trigger.getResource()) {
                    throw new ValidationException("Resource of execution '%s' of action '%s' does not match trigger resource.".formatted(execution.getName(), action.getName()));
                }
            }
            actions.add(action);
        }

        trigger.setRules(rules);
        trigger.setActions(actions);
    }

    //endregion

    //region Trigger Associations

    @Override
    public Map<ResourceEvent, List<UUID>> getTriggersAssociations(Resource resource, UUID associationObjectUuid) {
        List<TriggerAssociation> triggerAssociations = triggerAssociationRepository.findAllByResourceAndObjectUuidOrderByTriggerOrderAsc(resource, associationObjectUuid);

        Map<ResourceEvent, List<UUID>> triggersAssociationsEventMapping = new EnumMap<>(ResourceEvent.class);
        for (TriggerAssociation association : triggerAssociations) {
            triggersAssociationsEventMapping.computeIfAbsent(association.getEvent(), event -> new ArrayList<>()).add(association.getTriggerUuid());
        }

        return triggersAssociationsEventMapping;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.DETAIL)
    public void createTriggerAssociations(ResourceEvent event, Resource resource, UUID associationObjectUuid, List<UUID> triggerUuids, boolean replace) throws NotFoundException {
        if (resource != null && resource != event.getResource() && !event.getOverridingResources().contains(resource)) {
            throw new ValidationException("Resource %s cannot be associated with event %s.".formatted(resource.getLabel(), event.getLabel()));
        }

        if (replace) {
            triggerAssociationRepository.deleteByEventAndResourceAndObjectUuid(event, resource, associationObjectUuid);
        }

        UUID userUuid = null;
        try {
            userUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        } catch (ValidationException e) {
            // anonymous user
        }

        // categorize to ignore and normal triggers
        List<TriggerAssociation> triggers = new ArrayList<>();
        List<TriggerAssociation> ignoreTriggers = new ArrayList<>();
        for (UUID triggerUuid : triggerUuids) {
            Trigger trigger = getTriggerEntity(triggerUuid.toString());
            if (trigger.getResource() != event.getResource()) {
                throw new ValidationException("Trigger '%s' is for different resource (%s) than event '%s' (%s)".formatted(trigger.getName(), trigger.getResource().getLabel(), event.getLabel(), event.getResource().getLabel()));
            }
            if (trigger.getEvent() != null && trigger.getEvent() != event) {
                throw new ValidationException("Trigger '%s' is for different event (%s) than event '%s'".formatted(trigger.getName(), trigger.getEvent().getLabel(), event.getLabel()));
            }

            TriggerAssociation triggerAssociation = new TriggerAssociation();
            triggerAssociation.setTriggerUuid(triggerUuid);
            triggerAssociation.setResource(resource);
            triggerAssociation.setObjectUuid(associationObjectUuid);
            triggerAssociation.setEvent(event);
            triggerAssociation.setTriggeredBy(userUuid);
            // If it is an ignore trigger, the order is always -1, otherwise increment the order
            if (trigger.isIgnoreTrigger()) {
                ignoreTriggers.add(triggerAssociation);
            } else {
                triggers.add(triggerAssociation);
            }
        }

        // save in order
        int triggerOrder = -ignoreTriggers.size();
        for (TriggerAssociation ignoreTrigger : ignoreTriggers) {
            ignoreTrigger.setTriggerOrder(triggerOrder++);
            triggerAssociationRepository.save(ignoreTrigger);
        }
        for (TriggerAssociation trigger : triggers) {
            trigger.setTriggerOrder(triggerOrder++);
            triggerAssociationRepository.save(trigger);
        }
    }

    @Override
    public void deleteTriggerAssociations(Resource resource, UUID associationObjectUuid) {
        Long deletedAssociations = triggerAssociationRepository.deleteByResourceAndObjectUuid(resource, associationObjectUuid);
        logger.debug("Deleted {} trigger associations for {} with UUID {}.", deletedAssociations, resource.getLabel(), associationObjectUuid);
        // Do not delete history records, just remove association with the trigger association
        int clearedHistoryRecords = triggerHistoryRepository.removeTriggerAssociation(associationObjectUuid);
        logger.debug("Cleared trigger association from {} trigger history items for {} with UUID {}.", clearedHistoryRecords, resource.getLabel(), associationObjectUuid);
    }

    //endregion

    //region Trigger History

    @Override
    @ExternalAuthorization(resource = Resource.TRIGGER, action = ResourceAction.DETAIL)
    public List<TriggerHistoryDto> getTriggerHistory(String triggerUuid, String associationObjectUuid) {
        List<TriggerHistory> triggerHistories = triggerHistoryRepository.findAllByTriggerUuidAndTriggerAssociationObjectUuid(UUID.fromString(triggerUuid), UUID.fromString(associationObjectUuid));
        return triggerHistories.stream().map(TriggerHistory::mapToDto).toList();
    }

    @Override
    public TriggerHistorySummaryDto getTriggerHistorySummary(String associationObjectUuid) throws NotFoundException {
        List<TriggerHistory> triggerHistories = triggerHistoryRepository.findByTriggerAssociationObjectUuidOrderByTriggerUuidAscTriggeredAtAsc(UUID.fromString(associationObjectUuid));

        if (triggerHistories.isEmpty()) {
            throw new NotFoundException("Trigger association object", associationObjectUuid);
        }

        Map<UUID, TriggerHistoryObjectSummaryDto> objectsMapping = new HashMap<>();

        TriggerHistorySummaryDto resultDto = new TriggerHistorySummaryDto();

        // set initial summary data
        Trigger trigger = triggerHistories.getFirst().getTrigger();
        TriggerAssociation triggerAssociation = triggerHistories.getFirst().getTriggerAssociation();
        resultDto.setAssociationResource(triggerAssociation.getResource());
        resultDto.setAssociationObjectUuid(associationObjectUuid);
        resultDto.setObjectsResource(trigger.getResource());

        int objectsMatched = 0;
        int objectsIgnored = 0;
        for (TriggerHistory history : triggerHistories) {
            if (!history.getTriggerUuid().equals(trigger.getUuid())) {
                trigger = history.getTrigger();
            }


            UUID objectUuid = history.getObjectUuid() != null ? history.getObjectUuid() : history.getReferenceObjectUuid();
            TriggerHistoryObjectSummaryDto objectSummaryDto = objectsMapping.get(objectUuid);
            if (objectSummaryDto == null) {
                objectSummaryDto = new TriggerHistoryObjectSummaryDto();
                objectSummaryDto.setObjectUuid(history.getObjectUuid());
                objectSummaryDto.setReferenceObjectUuid(history.getReferenceObjectUuid());
                objectsMapping.put(objectUuid, objectSummaryDto);
            }

            // update match and ignore flags
            if (history.isConditionsMatched()) {
                if (!objectSummaryDto.isMatched()) {
                    objectSummaryDto.setMatched(true);
                    ++objectsMatched;
                }
                if (trigger.isIgnoreTrigger() && !objectSummaryDto.isIgnored()) {
                    objectSummaryDto.setIgnored(true);
                    ++objectsIgnored;
                }
            }

            // add trigger info with records
            TriggerHistoryObjectTriggerSummaryDto objectTriggerSummaryDto = new TriggerHistoryObjectTriggerSummaryDto();
            objectTriggerSummaryDto.setTriggerUuid(trigger.getUuid());
            objectTriggerSummaryDto.setTriggerName(trigger.getName());
            objectTriggerSummaryDto.setTriggeredAt(history.getTriggeredAt());
            objectTriggerSummaryDto.setMessage(history.getMessage());
            objectTriggerSummaryDto.setRecords(history.getRecords().stream().map(TriggerHistoryRecord::mapToDto).toList());
            objectSummaryDto.getTriggers().add(objectTriggerSummaryDto);
        }

        // update numbers of objects and add them to result
        resultDto.setObjectsEvaluated(objectsMapping.size());
        resultDto.setObjectsMatched(objectsMatched);
        resultDto.setObjectsIgnored(objectsIgnored);
        resultDto.setObjects(objectsMapping.values().stream().toList());

        return resultDto;
    }

    @Override
    public TriggerHistory createTriggerHistory(UUID triggerUuid, TriggerAssociation triggerAssociation, UUID objectUuid, UUID referenceObjectUuid, EventHistory eventHistory, Resource objectResource) {
        TriggerHistory triggerHistory = new TriggerHistory();
        triggerHistory.setTriggerUuid(triggerUuid);
        if (triggerAssociation != null) {
            triggerHistory.setTriggerAssociationUuid(triggerAssociation.getUuid());
            triggerHistory.setTriggerAssociation(triggerAssociation);
            triggerHistory.setEvent(triggerAssociation.getEvent());
        }
        triggerHistory.setObjectUuid(objectUuid);
        triggerHistory.setReferenceObjectUuid(referenceObjectUuid);
        triggerHistory.setTriggeredAt(OffsetDateTime.now());
        triggerHistory.setEventHistory(eventHistory);
        triggerHistory.setObjectResource(objectResource);

        try {
            triggerHistory.setTriggeredBy(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        } catch (ValidationException e) {
            // anonymous user
        }

        return triggerHistoryRepository.save(triggerHistory);
    }

    @Override
    public TriggerHistoryRecord createTriggerHistoryRecord(UUID triggerHistoryUuid, UUID conditionUuid, UUID executionUuid, String message) {
        TriggerHistoryRecord triggerHistoryRecord = new TriggerHistoryRecord();

        triggerHistoryRecord.setTriggerHistoryUuid(triggerHistoryUuid);
        triggerHistoryRecord.setConditionUuid(conditionUuid);
        triggerHistoryRecord.setExecutionUuid(executionUuid);
        triggerHistoryRecord.setMessage(message);
        triggerHistoryRecordRepository.save(triggerHistoryRecord);
        return triggerHistoryRecord;
    }

    //endregion

    private void validateTriggerRequest(TriggerType type, ResourceEvent event, boolean ignoreTrigger, Resource resource, List<String> actionsUuids) {
        if (resource == null || resource == Resource.ANY || resource == Resource.NONE) {
            throw new ValidationException("Property resource cannot be empty or None/Any");
        }

        if (type == TriggerType.EVENT) {
            if (event == null) {
                throw new ValidationException("When trigger type is Event, event has to be specified.");
            }
            if (event.getResource() != resource) {
                throw new ValidationException("Event resource (%s) and trigger (%s) resource has to match.".formatted(event.getResource().getLabel(), resource.getLabel()));
            }
        }

        if (!ignoreTrigger) {
            if (actionsUuids.isEmpty()) {
                throw new ValidationException("Trigger that is not ignore trigger must contain at least one action.");
            }
        } else {
            if (!actionsUuids.isEmpty()) {
                throw new ValidationException("Trigger that is ignore trigger cannot have actions.");
            }
        }
    }
}
