package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.RuleController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.RuleExternalService;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class RuleControllerImpl implements RuleController {

    private RuleExternalService ruleService;

    @Autowired
    public void setRuleService(RuleExternalService ruleService) {
        this.ruleService = ruleService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.CONDITION, operation = Operation.LIST)
    public List<ConditionDto> listConditions(Resource resource) {
        return ruleService.listConditions(resource);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.CONDITION, operation = Operation.CREATE)
    public ConditionDto createCondition(ConditionRequestDto request) throws AlreadyExistException {
        return ruleService.createCondition(request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.CONDITION, operation = Operation.DETAIL)
    public ConditionDto getCondition(@LogResource(uuid = true) String conditionUuid) throws NotFoundException {
        return ruleService.getCondition(conditionUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.CONDITION, operation = Operation.UPDATE)
    public ConditionDto updateCondition(@LogResource(uuid = true) String conditionUuid, UpdateConditionRequestDto request) throws NotFoundException {
        return ruleService.updateCondition(conditionUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.CONDITION, operation = Operation.DELETE)
    public void deleteCondition(@LogResource(uuid = true) String conditionUuid) throws NotFoundException {
        ruleService.deleteCondition(conditionUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.LIST)
    public List<RuleDto> listRules(Resource resource) {
        return ruleService.listRules(resource);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.CREATE)
    public RuleDetailDto createRule(RuleRequestDto request) throws NotFoundException, AlreadyExistException {
        return ruleService.createRule(request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.DETAIL)
    public RuleDetailDto getRule(@LogResource(uuid = true) String ruleUuid) throws NotFoundException {
        return ruleService.getRule(ruleUuid);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.UPDATE)
    public RuleDetailDto updateRule(@LogResource(uuid = true) String ruleUuid, UpdateRuleRequestDto request) throws NotFoundException {
        return ruleService.updateRule(ruleUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.DELETE)
    public void deleteRule(@LogResource(uuid = true) String ruleUuid) throws NotFoundException {
        ruleService.deleteRule(ruleUuid);
    }
}
