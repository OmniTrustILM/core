package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.dao.entity.notifications.NotificationProfile;
import com.czertainly.core.dao.entity.workflows.*;
import com.czertainly.core.dao.repository.notifications.NotificationProfileRepository;
import com.czertainly.core.dao.repository.workflows.*;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.ActionExternalService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class ActionServiceImpl implements ActionExternalService {

    private ExecutionRepository executionRepository;
    private ExecutionItemRepository executionItemRepository;
    private ActionRepository actionRepository;

    private NotificationProfileRepository notificationProfileRepository;


    @Autowired
    public void setExecutionRepository(ExecutionRepository executionRepository) {
        this.executionRepository = executionRepository;
    }

    @Autowired
    public void setExecutionItemRepository(ExecutionItemRepository executionItemRepository) {
        this.executionItemRepository = executionItemRepository;
    }

    @Autowired
    public void setActionRepository(ActionRepository actionRepository) {
        this.actionRepository = actionRepository;
    }

    @Autowired
    public void setNotificationProfileRepository(NotificationProfileRepository notificationProfileRepository) {
        this.notificationProfileRepository = notificationProfileRepository;
    }


    //region Executions

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.LIST)
    public List<ExecutionDto> listExecutions(Resource resource) {
        if (resource == null || resource == Resource.ANY)
            return executionRepository.findAllWithItemsBy().stream().map(Execution::mapToDto).toList();
        return executionRepository.findAllByResource(resource).stream().map(Execution::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.DETAIL)
    public ExecutionDto getExecution(String executionUuid) throws NotFoundException {
        return executionRepository.findWithItemsByUuid(UUID.fromString(executionUuid)).orElseThrow(() -> new NotFoundException(Execution.class, executionUuid)).mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.CREATE)
    public ExecutionDto createExecution(ExecutionRequestDto request) throws AlreadyExistException, NotFoundException {
        if (request.getItems().isEmpty()) {
            throw new ValidationException("Cannot create an execution without any execution items.");
        }
        if (request.getName() == null) {
            throw new ValidationException("Property name cannot be empty.");
        }
        if (request.getResource() == null) {
            throw new ValidationException("Property resource cannot be empty.");
        }

        if (executionRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("Execution with same name already exists.");
        }

        Execution execution = new Execution();
        execution.setName(request.getName());
        execution.setDescription(request.getDescription());
        execution.setType(request.getType());
        execution.setResource(request.getResource());
        execution.setItems(createExecutionItems(request.getItems(), execution));
        executionRepository.save(execution);

        return execution.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.UPDATE)
    public ExecutionDto updateExecution(String executionUuid, UpdateExecutionRequestDto request) throws NotFoundException {
        if (request.getItems().isEmpty()) {
            throw new ValidationException("Cannot create an execution without any execution items.");
        }

        Execution execution = executionRepository.findByUuid(SecuredUUID.fromString(executionUuid)).orElseThrow(() -> new NotFoundException(Execution.class, executionUuid));
        executionItemRepository.deleteByExecution(execution);

        execution.setDescription(request.getDescription());
        execution.setItems(createExecutionItems(request.getItems(), execution));

        executionRepository.save(execution);

        return execution.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.DELETE)
    public void deleteExecution(String executionUuid) throws NotFoundException {
        Execution execution = executionRepository.findWithActionsByUuid(UUID.fromString(executionUuid)).orElseThrow(() -> new NotFoundException(Execution.class, executionUuid));

        // check if not associated to actions
        if (!execution.getActions().isEmpty()) {
            throw new ValidationException(String.format("Cannot delete execution %s. It is associated to following actions: %s.", execution.getName(), String.join(", ", execution.getActions().stream().map(Action::getName).toList())));
        }

        executionRepository.delete(execution);
    }

    private Set<ExecutionItem> createExecutionItems(List<ExecutionItemRequestDto> executionItemRequestDtos, Execution execution) throws NotFoundException {
        Set<ExecutionItem> executionItems = new HashSet<>();
        for (ExecutionItemRequestDto executionItemRequestDto : executionItemRequestDtos) {
            ExecutionItem executionItem = switch (execution.getType()) {
                case SET_FIELD -> createSetFieldExecutionItem(execution, executionItemRequestDto);
                case SEND_NOTIFICATION -> createSendNotificationExecutionItem(execution, executionItemRequestDto);
            };

            executionItems.add(executionItem);
        }
        return executionItems;
    }

    private ExecutionItem createSetFieldExecutionItem(Execution execution, ExecutionItemRequestDto executionItemRequestDto) {
        if (executionItemRequestDto.getFieldSource() == null || executionItemRequestDto.getFieldIdentifier() == null) {
            throw new ValidationException("Missing field source or field identifier in an execution.");
        }
        if (executionItemRequestDto.getFieldSource() != FilterFieldSource.PROPERTY && executionItemRequestDto.getFieldSource() != FilterFieldSource.CUSTOM) {
            throw new ValidationException("Missing field source or field identifier in an execution.");
        }
        if (execution.getResource() == Resource.ANY || execution.getResource() == Resource.NONE) {
            throw new ValidationException("Resource %s is not allowed for execution type %s".formatted(execution.getResource().getLabel(), execution.getType().getLabel()));
        }

        ExecutionItem executionItem = new ExecutionItem();
        executionItem.setExecution(execution);
        executionItem.setFieldSource(executionItemRequestDto.getFieldSource());
        executionItem.setFieldIdentifier(executionItemRequestDto.getFieldIdentifier());
        if (executionItem.getFieldSource() != FilterFieldSource.CUSTOM) {
            executionItem.setData(executionItemRequestDto.getData());
        } else {
            try {
                if (executionItemRequestDto.getData() == null) {
                    executionItem.setData(new ArrayList<BaseAttributeContentV3<?>>());
                } else {
                    AttributeContentType attributeContentType = AttributeContentType.valueOf(executionItemRequestDto.getFieldIdentifier().substring(executionItemRequestDto.getFieldIdentifier().indexOf("|") + 1));
                    List<BaseAttributeContentV3<?>> contentItems = AttributeDefinitionUtils.createAttributeContentFromString(attributeContentType, executionItemRequestDto.getData() instanceof ArrayList<?> ? (List<String>) executionItemRequestDto.getData() : List.of(executionItemRequestDto.getData().toString()));
                    executionItem.setData(contentItems);
                }
            } catch (IllegalArgumentException e) {
                throw new ValidationException("Unknown content type for custom attribute with field identifier: " + executionItemRequestDto.getFieldIdentifier());
            }
        }

        return executionItem;
    }

    private ExecutionItem createSendNotificationExecutionItem(Execution execution, ExecutionItemRequestDto executionItemRequestDto) throws NotFoundException {
        if (executionItemRequestDto.getNotificationProfileUuid() == null) {
            throw new ValidationException("Notification profile UUID is required for execution type send notification");
        }

        SecuredUUID notificationProfileUuid = SecuredUUID.fromString(executionItemRequestDto.getNotificationProfileUuid());
        NotificationProfile notificationProfile = notificationProfileRepository.findByUuid(notificationProfileUuid).orElseThrow(() -> new NotFoundException(NotificationProfile.class, notificationProfileUuid));

        ExecutionItem executionItem = new ExecutionItem();
        executionItem.setExecution(execution);
        executionItem.setNotificationProfile(notificationProfile);
        executionItem.setNotificationProfileUuid(notificationProfileUuid.getValue());

        return executionItem;
    }

    //endregion

    //region Actions

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.LIST)
    public List<ActionDto> listActions(Resource resource) {
        if (resource == null || resource == Resource.ANY)
            return actionRepository.findAll().stream().map(Action::mapToDto).toList();
        return actionRepository.findAllByResource(resource).stream().map(Action::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.DETAIL)
    public ActionDetailDto getAction(String actionUuid) throws NotFoundException {
        return actionRepository.findByUuid(SecuredUUID.fromString(actionUuid)).orElseThrow(() -> new NotFoundException(Action.class, actionUuid)).mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.CREATE)
    public ActionDetailDto createAction(ActionRequestDto request) throws AlreadyExistException, NotFoundException {
        if (request.getName() == null) {
            throw new ValidationException("Property name cannot be empty.");
        }
        if (request.getResource() == null) {
            throw new ValidationException("Property resource cannot be empty.");
        }

        if (actionRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("Action with same name already exists.");
        }

        if (request.getExecutionsUuids().isEmpty()) {
            throw new ValidationException("Action has to contain at least one execution.");
        }

        Action action = new Action();
        Set<Execution> executions = new HashSet<>();

        for (String executionUuid : request.getExecutionsUuids()) {
            Execution execution = executionRepository.findByUuid(SecuredUUID.fromString(executionUuid)).orElseThrow(() -> new NotFoundException(Execution.class, executionUuid));
            if (request.getResource() != Resource.ANY && execution.getResource() != Resource.ANY && execution.getResource() != request.getResource()) {
                throw new ValidationException("Resource of execution '%s' does not match action resource.".formatted(execution.getName()));
            }
            executions.add(execution);
        }

        action.setName(request.getName());
        action.setDescription(request.getDescription());
        action.setResource(request.getResource());
        action.setExecutions(executions);

        actionRepository.save(action);
        return action.mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.UPDATE)
    public ActionDetailDto updateAction(String actionUuid, UpdateActionRequestDto request) throws NotFoundException {
        if (request.getExecutionsUuids().isEmpty()) {
            throw new ValidationException("Action has to contain at least one execution.");
        }

        Set<Execution> executions = new HashSet<>();
        Action action = actionRepository.findWithTriggersByUuid(UUID.fromString(actionUuid)).orElseThrow(() -> new NotFoundException(Action.class, actionUuid));
        Set<Resource> associatedTriggersResources = action.getTriggers().stream().map(Trigger::getResource).collect(Collectors.toSet());

        for (String executionUuid : request.getExecutionsUuids()) {
            Execution execution = executionRepository.findByUuid(SecuredUUID.fromString(executionUuid)).orElseThrow(() -> new NotFoundException(Execution.class, executionUuid));
            if (action.getResource() != Resource.ANY && execution.getResource() != Resource.ANY && execution.getResource() != action.getResource()) {
                throw new ValidationException("Resource of execution '%s' does not match action resource.".formatted(execution.getName()));
            }
            if (execution.getResource() != Resource.ANY && (associatedTriggersResources.size() > 1 || (associatedTriggersResources.size() == 1 && !associatedTriggersResources.contains(execution.getResource())))) {
                throw new ValidationException("Resource of execution '%s' does not match resource of triggers associated with action.".formatted(execution.getName()));
            }
            executions.add(execution);
        }

        action.setDescription(request.getDescription());
        action.setExecutions(executions);

        actionRepository.save(action);
        return action.mapToDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACTION, action = ResourceAction.DELETE)
    public void deleteAction(String actionUuid) throws NotFoundException {
        Action action = actionRepository.findWithTriggersByUuid(UUID.fromString(actionUuid)).orElseThrow(() -> new NotFoundException(Action.class, actionUuid));

        // check if not associated to triggers
        if (!action.getTriggers().isEmpty()) {
            throw new ValidationException(String.format("Cannot delete action %s. It is associated to following triggers: %s.", action.getName(), String.join(", ", action.getTriggers().stream().map(Trigger::getName).toList())));
        }

        actionRepository.delete(action);
    }

    //endregion
}
