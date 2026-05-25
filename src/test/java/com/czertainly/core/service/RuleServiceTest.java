package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class RuleServiceTest extends BaseSpringBootTest {

    @Autowired
    RuleExternalService ruleService;

    @Autowired
    ActionExternalService actionService;

    @Autowired
    TriggerExternalService triggerService;

    ConditionDto conditionDto;
    ConditionItemRequestDto conditionItemRequestDto;

    ExecutionDto executionDto;
//    ExecutionRequestDto executionRequestDto;
    ExecutionItemRequestDto executionItemRequestDto;


    @BeforeEach
    public void setUp() throws AlreadyExistException, NotFoundException {
        conditionItemRequestDto = new ConditionItemRequestDto();
        conditionItemRequestDto.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequestDto.setFieldIdentifier("identifier");
        conditionItemRequestDto.setOperator(FilterConditionOperator.EQUALS);
        conditionItemRequestDto.setValue("123");

        ConditionRequestDto conditionRequestDto = new ConditionRequestDto();
        conditionRequestDto.setName("TestCond");
        conditionRequestDto.setResource(Resource.CERTIFICATE);
        conditionRequestDto.setType(ConditionType.CHECK_FIELD);
        conditionRequestDto.setItems(List.of(conditionItemRequestDto));
        conditionDto = ruleService.createCondition(conditionRequestDto);

        executionItemRequestDto = new ExecutionItemRequestDto();
        executionItemRequestDto.setFieldSource(FilterFieldSource.PROPERTY);
        executionItemRequestDto.setFieldIdentifier("identifier");

        ExecutionRequestDto executionRequestDto = new ExecutionRequestDto();
        executionRequestDto.setName("TestExecution");
        executionRequestDto.setType(ExecutionType.SET_FIELD);
        executionRequestDto.setResource(Resource.CERTIFICATE);
        executionRequestDto.setItems(List.of(executionItemRequestDto));
        executionDto = actionService.createExecution(executionRequestDto);
    }


    @Test
    public void testRule() throws NotFoundException, AlreadyExistException {
        RuleRequestDto ruleRequestDto = new RuleRequestDto();
        ruleRequestDto.setName("name");
        ruleRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> ruleService.createRule(ruleRequestDto));

        ruleRequestDto.setConditionsUuids(List.of(conditionDto.getUuid()));
        RuleDetailDto ruleDetailDto = ruleService.createRule(ruleRequestDto);
        Assertions.assertNotNull(ruleDetailDto);

        UpdateRuleRequestDto updateRuleRequestDto = new UpdateRuleRequestDto();
        updateRuleRequestDto.setDescription("description");
        updateRuleRequestDto.setConditionsUuids(ruleRequestDto.getConditionsUuids());
        Assertions.assertEquals("description", ruleService.updateRule(ruleDetailDto.getUuid(), updateRuleRequestDto).getDescription());

        Assertions.assertNotNull(ruleService.getRule(ruleDetailDto.getUuid()));

        Assertions.assertNotEquals(0, ruleService.listRules(null).size());

        ruleService.deleteRule(ruleDetailDto.getUuid());

        Assertions.assertThrows(NotFoundException.class, () -> ruleService.getRule(ruleDetailDto.getUuid()));

    }

    @Test
    public void testCondition() throws NotFoundException, AlreadyExistException {
        ConditionRequestDto conditionRequestDto = new ConditionRequestDto();
        conditionRequestDto.setName("name");
        conditionRequestDto.setType(ConditionType.CHECK_FIELD);
        conditionRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> ruleService.createCondition(conditionRequestDto));

        conditionRequestDto.setItems(List.of(conditionItemRequestDto));
        ConditionDto conditionGroupDetailDto = ruleService.createCondition(conditionRequestDto);
        Assertions.assertNotNull(conditionGroupDetailDto);

        UpdateConditionRequestDto updateConditionGroupRequestDto = new UpdateConditionRequestDto();
        updateConditionGroupRequestDto.setDescription("description");
        updateConditionGroupRequestDto.setItems(conditionRequestDto.getItems());
        Assertions.assertEquals("description", ruleService.updateCondition(conditionGroupDetailDto.getUuid(), updateConditionGroupRequestDto).getDescription());

        Assertions.assertNotNull(ruleService.getCondition(conditionGroupDetailDto.getUuid()));

        Assertions.assertNotEquals(0, ruleService.listConditions(null).size());
        ruleService.deleteCondition(conditionGroupDetailDto.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> ruleService.getCondition(conditionGroupDetailDto.getUuid()));
    }

    @Test
    public void testTrigger() throws NotFoundException, AlreadyExistException {
        TriggerRequestDto triggerRequestDto = new TriggerRequestDto();
        triggerRequestDto.setName("name");
        triggerRequestDto.setResource(Resource.CERTIFICATE);
        triggerRequestDto.setType(TriggerType.EVENT);
        triggerRequestDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        Assertions.assertThrows(ValidationException.class, () -> triggerService.createTrigger(triggerRequestDto));

        ActionRequestDto actionRequestDto = new ActionRequestDto();
        actionRequestDto.setName("TestAction");
        actionRequestDto.setResource(Resource.CERTIFICATE);
        actionRequestDto.setExecutionsUuids(List.of(executionDto.getUuid()));
        ActionDto actionDto = actionService.createAction(actionRequestDto);

        triggerRequestDto.setActionsUuids(List.of(actionDto.getUuid()));
        TriggerDetailDto triggerDetailDto = triggerService.createTrigger(triggerRequestDto);
        Assertions.assertNotNull(triggerDetailDto);

        UpdateTriggerRequestDto updateTriggerRequestDto = new UpdateTriggerRequestDto();
        updateTriggerRequestDto.setDescription("description");
        updateTriggerRequestDto.setType(TriggerType.EVENT);
        updateTriggerRequestDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        updateTriggerRequestDto.setResource(Resource.CERTIFICATE);
        updateTriggerRequestDto.setActionsUuids(triggerRequestDto.getActionsUuids());
        Assertions.assertEquals("description", triggerService.updateTrigger(triggerDetailDto.getUuid(), updateTriggerRequestDto).getDescription());

        Assertions.assertNotNull(triggerService.getTrigger(triggerDetailDto.getUuid()));

        Assertions.assertNotEquals(0, triggerService.listTriggers(null).size());

        triggerService.deleteTrigger(triggerDetailDto.getUuid());

        Assertions.assertThrows(NotFoundException.class, () -> triggerService.getTrigger(triggerDetailDto.getUuid()));

    }


    @Test
    public void testExecution() throws NotFoundException, AlreadyExistException {
        ExecutionRequestDto executionRequestDto = new ExecutionRequestDto();
        executionRequestDto.setName("name");
        executionRequestDto.setType(ExecutionType.SET_FIELD);
        executionRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> actionService.createExecution(executionRequestDto));
        executionRequestDto.setItems(List.of(executionItemRequestDto));
        ExecutionDto executionDto = actionService.createExecution(executionRequestDto);
        Assertions.assertNotNull(executionDto);

        UpdateExecutionRequestDto updateActionGroupRequestDto = new UpdateExecutionRequestDto();
        updateActionGroupRequestDto.setDescription("description");
        updateActionGroupRequestDto.setItems(executionRequestDto.getItems());
        Assertions.assertEquals("description", actionService.updateExecution(executionDto.getUuid(), updateActionGroupRequestDto).getDescription());

        Assertions.assertNotNull(actionService.getExecution(executionDto.getUuid()));

        Assertions.assertNotEquals(0, actionService.listExecutions(null).size());
        actionService.deleteExecution(executionDto.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> actionService.getExecution(executionDto.getUuid()));
    }


}
