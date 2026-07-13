package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.*;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

class RuleServiceITest extends BaseSpringBootTest {

    @Autowired
    RuleExternalService ruleService;

    @Autowired
    ActionExternalService actionService;

    @Autowired
    TriggerExternalService triggerService;

    ConditionDto conditionDto;
    ConditionItemRequestDto conditionItemRequestDto;

    ExecutionDto executionDto;
    ExecutionItemRequestDto executionItemRequestDto;


    @BeforeEach
    void setUp() throws AlreadyExistException, NotFoundException {
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
    void testRule() throws NotFoundException, AlreadyExistException {
        RuleRequestDto ruleRequestDto = new RuleRequestDto();
        ruleRequestDto.setName("name");
        ruleRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> ruleService.createRule(ruleRequestDto));

        ruleRequestDto.setConditionsUuids(List.of(conditionDto.getUuid()));
        RuleDetailDto ruleDetailDto = ruleService.createRule(ruleRequestDto);
        Assertions.assertNotNull(ruleDetailDto);

        UpdateRuleRequestDto updateRuleRequestDto = new UpdateRuleRequestDto();
        updateRuleRequestDto.setName("name");
        updateRuleRequestDto.setDescription("description");
        updateRuleRequestDto.setConditionsUuids(ruleRequestDto.getConditionsUuids());
        Assertions.assertEquals("description", ruleService.updateRule(ruleDetailDto.getUuid(), updateRuleRequestDto).getDescription());

        Assertions.assertNotNull(ruleService.getRule(ruleDetailDto.getUuid()));

        Assertions.assertNotEquals(0, ruleService.listRules(null).size());

        ruleService.deleteRule(ruleDetailDto.getUuid());

        Assertions.assertThrows(NotFoundException.class, () -> ruleService.getRule(ruleDetailDto.getUuid()));

    }

    @Test
    void testCondition() throws NotFoundException, AlreadyExistException {
        ConditionRequestDto conditionRequestDto = new ConditionRequestDto();
        conditionRequestDto.setName("name");
        conditionRequestDto.setType(ConditionType.CHECK_FIELD);
        conditionRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> ruleService.createCondition(conditionRequestDto));

        conditionRequestDto.setItems(List.of(conditionItemRequestDto));
        ConditionDto conditionGroupDetailDto = ruleService.createCondition(conditionRequestDto);
        Assertions.assertNotNull(conditionGroupDetailDto);

        UpdateConditionRequestDto updateConditionGroupRequestDto = new UpdateConditionRequestDto();
        updateConditionGroupRequestDto.setName("name");
        updateConditionGroupRequestDto.setDescription("description");
        updateConditionGroupRequestDto.setItems(conditionRequestDto.getItems());
        Assertions.assertEquals("description", ruleService.updateCondition(conditionGroupDetailDto.getUuid(), updateConditionGroupRequestDto).getDescription());

        Assertions.assertNotNull(ruleService.getCondition(conditionGroupDetailDto.getUuid()));

        Assertions.assertNotEquals(0, ruleService.listConditions(null).size());
        ruleService.deleteCondition(conditionGroupDetailDto.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> ruleService.getCondition(conditionGroupDetailDto.getUuid()));
    }

    @Test
    void testTrigger() throws NotFoundException, AlreadyExistException {
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
        updateTriggerRequestDto.setName("name");
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
    void testExecution() throws NotFoundException, AlreadyExistException {
        ExecutionRequestDto executionRequestDto = new ExecutionRequestDto();
        executionRequestDto.setName("name");
        executionRequestDto.setType(ExecutionType.SET_FIELD);
        executionRequestDto.setResource(Resource.CERTIFICATE);
        Assertions.assertThrows(ValidationException.class, () -> actionService.createExecution(executionRequestDto));
        executionRequestDto.setItems(List.of(executionItemRequestDto));
        ExecutionDto executionDto2 = actionService.createExecution(executionRequestDto);
        Assertions.assertNotNull(executionDto2);

        UpdateExecutionRequestDto updateActionGroupRequestDto = new UpdateExecutionRequestDto();
        updateActionGroupRequestDto.setName("name");
        updateActionGroupRequestDto.setDescription("description");
        updateActionGroupRequestDto.setItems(executionRequestDto.getItems());
        ExecutionDto updatedExecution = actionService.updateExecution(executionDto2.getUuid(), updateActionGroupRequestDto);
        Assertions.assertEquals("description", updatedExecution.getDescription());
        Assertions.assertEquals(executionDto2.getName(), updatedExecution.getName());

        Assertions.assertNotNull(actionService.getExecution(executionDto2.getUuid()));

        Assertions.assertNotEquals(0, actionService.listExecutions(null).size());
        actionService.deleteExecution(executionDto2.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> actionService.getExecution(executionDto2.getUuid()));
    }

    @Test
    void testUpdateConditionNameUniqueness() throws AlreadyExistException, NotFoundException {
        ConditionRequestDto reqA = new ConditionRequestDto();
        reqA.setName("CondA");
        reqA.setResource(Resource.CERTIFICATE);
        reqA.setType(ConditionType.CHECK_FIELD);
        reqA.setItems(List.of(conditionItemRequestDto));
        ConditionDto condA = ruleService.createCondition(reqA);

        ConditionRequestDto reqB = new ConditionRequestDto();
        reqB.setName("CondB");
        reqB.setResource(Resource.CERTIFICATE);
        reqB.setType(ConditionType.CHECK_FIELD);
        reqB.setItems(List.of(conditionItemRequestDto));
        ruleService.createCondition(reqB);

        UpdateConditionRequestDto update = new UpdateConditionRequestDto();
        update.setItems(List.of(conditionItemRequestDto));

        update.setName("CondA");
        Assertions.assertDoesNotThrow(() -> ruleService.updateCondition(condA.getUuid(), update), "Updating with same name should succeed");

        update.setName("CondC");
        Assertions.assertEquals("CondC", ruleService.updateCondition(condA.getUuid(), update).getName(), "Name should change to the new value");

        update.setName("CondB");
        Assertions.assertThrows(AlreadyExistException.class, () -> ruleService.updateCondition(condA.getUuid(), update), "Updating with another object's name should fail");
    }

    @Test
    void testUpdateRuleNameUniqueness() throws AlreadyExistException, NotFoundException {
        RuleRequestDto reqA = new RuleRequestDto();
        reqA.setName("RuleA");
        reqA.setResource(Resource.CERTIFICATE);
        reqA.setConditionsUuids(List.of(conditionDto.getUuid()));
        RuleDetailDto ruleA = ruleService.createRule(reqA);

        RuleRequestDto reqB = new RuleRequestDto();
        reqB.setName("RuleB");
        reqB.setResource(Resource.CERTIFICATE);
        reqB.setConditionsUuids(List.of(conditionDto.getUuid()));
        ruleService.createRule(reqB);

        UpdateRuleRequestDto update = new UpdateRuleRequestDto();
        update.setConditionsUuids(List.of(conditionDto.getUuid()));

        update.setName("RuleA");
        Assertions.assertDoesNotThrow(() -> ruleService.updateRule(ruleA.getUuid(), update), "Updating with same name should succeed");

        update.setName("RuleC");
        Assertions.assertEquals("RuleC", ruleService.updateRule(ruleA.getUuid(), update).getName(), "Name should change to the new value");

        update.setName("RuleB");
        Assertions.assertThrows(AlreadyExistException.class, () -> ruleService.updateRule(ruleA.getUuid(), update), "Updating with another object's name should fail");
    }

    @Test
    void testUpdateExecutionNameUniqueness() throws AlreadyExistException, NotFoundException {
        ExecutionRequestDto reqA = new ExecutionRequestDto();
        reqA.setName("ExecA");
        reqA.setType(ExecutionType.SET_FIELD);
        reqA.setResource(Resource.CERTIFICATE);
        reqA.setItems(List.of(executionItemRequestDto));
        ExecutionDto execA = actionService.createExecution(reqA);

        ExecutionRequestDto reqB = new ExecutionRequestDto();
        reqB.setName("ExecB");
        reqB.setType(ExecutionType.SET_FIELD);
        reqB.setResource(Resource.CERTIFICATE);
        reqB.setItems(List.of(executionItemRequestDto));
        actionService.createExecution(reqB);

        UpdateExecutionRequestDto update = new UpdateExecutionRequestDto();
        update.setItems(List.of(executionItemRequestDto));

        update.setName("ExecA");
        Assertions.assertDoesNotThrow(() -> actionService.updateExecution(execA.getUuid(), update), "Updating with same name should succeed");

        update.setName("ExecC");
        Assertions.assertEquals("ExecC", actionService.updateExecution(execA.getUuid(), update).getName(), "Name should change to the new value");

        update.setName("ExecB");
        Assertions.assertThrows(AlreadyExistException.class, () -> actionService.updateExecution(execA.getUuid(), update), "Updating with another object's name should fail");
    }

    @Test
    void testUpdateActionNameUniqueness() throws AlreadyExistException, NotFoundException {
        ActionRequestDto reqA = new ActionRequestDto();
        reqA.setName("ActionA");
        reqA.setResource(Resource.CERTIFICATE);
        reqA.setExecutionsUuids(List.of(executionDto.getUuid()));
        ActionDetailDto actionA = actionService.createAction(reqA);

        ActionRequestDto reqB = new ActionRequestDto();
        reqB.setName("ActionB");
        reqB.setResource(Resource.CERTIFICATE);
        reqB.setExecutionsUuids(List.of(executionDto.getUuid()));
        actionService.createAction(reqB);

        UpdateActionRequestDto update = new UpdateActionRequestDto();
        update.setExecutionsUuids(List.of(executionDto.getUuid()));

        update.setName("ActionA");
        Assertions.assertDoesNotThrow(() -> actionService.updateAction(actionA.getUuid(), update), "Updating with same name should succeed");

        update.setName("ActionC");
        Assertions.assertEquals("ActionC", actionService.updateAction(actionA.getUuid(), update).getName(), "Name should change to the new value");

        update.setName("ActionB");
        Assertions.assertThrows(AlreadyExistException.class, () -> actionService.updateAction(actionA.getUuid(), update), "Updating with another object's name should fail");
    }

    @Test
    void testUpdateTriggerNameUniqueness() throws AlreadyExistException, NotFoundException {
        ActionRequestDto actionReq = new ActionRequestDto();
        actionReq.setName("NameTestAction");
        actionReq.setResource(Resource.CERTIFICATE);
        actionReq.setExecutionsUuids(List.of(executionDto.getUuid()));
        ActionDto action = actionService.createAction(actionReq);

        TriggerRequestDto reqA = new TriggerRequestDto();
        reqA.setName("TriggerA");
        reqA.setResource(Resource.CERTIFICATE);
        reqA.setType(TriggerType.EVENT);
        reqA.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        reqA.setActionsUuids(List.of(action.getUuid()));
        TriggerDetailDto triggerA = triggerService.createTrigger(reqA);

        TriggerRequestDto reqB = new TriggerRequestDto();
        reqB.setName("TriggerB");
        reqB.setResource(Resource.CERTIFICATE);
        reqB.setType(TriggerType.EVENT);
        reqB.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        reqB.setActionsUuids(List.of(action.getUuid()));
        triggerService.createTrigger(reqB);

        UpdateTriggerRequestDto update = new UpdateTriggerRequestDto();
        update.setType(TriggerType.EVENT);
        update.setResource(Resource.CERTIFICATE);
        update.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        update.setActionsUuids(List.of(action.getUuid()));

        update.setName("TriggerA");
        Assertions.assertDoesNotThrow(() -> triggerService.updateTrigger(triggerA.getUuid(), update), "Updating with same name should succeed");

        update.setName("TriggerC");
        Assertions.assertEquals("TriggerC", triggerService.updateTrigger(triggerA.getUuid(), update).getName(), "Name should change to the new value");

        update.setName("TriggerB");
        Assertions.assertThrows(AlreadyExistException.class, () -> triggerService.updateTrigger(triggerA.getUuid(), update), "Updating with another object's name should fail");
    }

}
