package com.czertainly.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.workflows.*;

import java.util.List;

public interface ActionExternalService {

    List<ExecutionDto> listExecutions(Resource resource);
    ExecutionDto getExecution(String executionUuid) throws NotFoundException;
    ExecutionDto createExecution(ExecutionRequestDto request) throws AlreadyExistException, NotFoundException;
    ExecutionDto updateExecution(String executionUuid, UpdateExecutionRequestDto request) throws NotFoundException, AlreadyExistException;
    void deleteExecution(String executionUuid) throws NotFoundException;

    List<ActionDto> listActions(Resource resource);
    ActionDetailDto getAction(String actionUuid) throws NotFoundException;
    ActionDetailDto createAction(ActionRequestDto request) throws AlreadyExistException, NotFoundException;
    ActionDetailDto updateAction(String actionUuid, UpdateActionRequestDto request) throws NotFoundException, AlreadyExistException;
    void deleteAction(String actionUuid) throws NotFoundException;
}
