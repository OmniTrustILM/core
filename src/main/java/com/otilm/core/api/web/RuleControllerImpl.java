package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.RuleController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.RuleDetailDto;
import com.otilm.api.model.core.workflows.RuleDto;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.UpdateConditionRequestDto;
import com.otilm.api.model.core.workflows.UpdateRuleRequestDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

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
    public ConditionDto updateCondition(@LogResource(uuid = true) String conditionUuid,
            UpdateConditionRequestDto request) throws NotFoundException, AlreadyExistException {
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
    public RuleDetailDto updateRule(@LogResource(uuid = true) String ruleUuid, UpdateRuleRequestDto request)
            throws NotFoundException, AlreadyExistException {
        return ruleService.updateRule(ruleUuid, request);
    }

    @Override
    @AuditLogged(module = Module.WORKFLOWS, resource = Resource.RULE, operation = Operation.DELETE)
    public void deleteRule(@LogResource(uuid = true) String ruleUuid) throws NotFoundException {
        ruleService.deleteRule(ruleUuid);
    }
}
