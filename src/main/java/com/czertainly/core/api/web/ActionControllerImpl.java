package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.ActionController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.ActionExternalService;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ActionControllerImpl implements ActionController {

    private ActionExternalService actionService;

    @Autowired
    public void setActionService(ActionExternalService actionService) {
        this.actionService = actionService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.EXECUTION, operation = Operation.LIST)
    public List<ExecutionDto> listExecutions(Resource resource) {
        return actionService.listExecutions(resource);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.EXECUTION, operation = Operation.CREATE)
    public ExecutionDto createExecution(ExecutionRequestDto request) throws AlreadyExistException, NotFoundException {
        return actionService.createExecution(request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.EXECUTION, operation = Operation.DETAIL)
    public ExecutionDto getExecution(@LogResource(uuid = true) String executionUuid) throws NotFoundException {
        return actionService.getExecution(executionUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.EXECUTION, operation = Operation.UPDATE)
    public ExecutionDto updateExecution(@LogResource(uuid = true) String executionUuid, UpdateExecutionRequestDto request) throws NotFoundException {
        return actionService.updateExecution(executionUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.EXECUTION, operation = Operation.DELETE)
    public void deleteExecution(@LogResource(uuid = true) String executionUuid) throws NotFoundException {
        actionService.deleteExecution(executionUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.ACTION, operation = Operation.LIST)
    public List<ActionDto> listActions(Resource resource) {
        return actionService.listActions(resource);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.ACTION, operation = Operation.CREATE)
    public ActionDetailDto createAction(ActionRequestDto request) throws NotFoundException, AlreadyExistException {
        return actionService.createAction(request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.ACTION, operation = Operation.DETAIL)
    public ActionDetailDto getAction(@LogResource(uuid = true) String actionUuid) throws NotFoundException {
        return actionService.getAction(actionUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.ACTION, operation = Operation.UPDATE)
    public ActionDetailDto updateAction(@LogResource(uuid = true) String actionUuid, UpdateActionRequestDto request) throws NotFoundException {
        return actionService.updateAction(actionUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.ACTION, operation = Operation.DELETE)
    public void deleteAction(@LogResource(uuid = true) String actionUuid) throws NotFoundException {
        actionService.deleteAction(actionUuid);
    }
}
