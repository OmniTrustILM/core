package com.otilm.core.evaluator;

import com.otilm.api.exception.RuleException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.ComplianceInternalRule;
import com.otilm.core.dao.entity.workflows.*;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface ITriggerEvaluator<T> {

    default TriggerHistory evaluateTrigger(Trigger trigger, TriggerAssociation triggerAssociation, T object, UUID referenceObjectUuid, Object data, EventHistory eventHistory) throws RuleException {
        return evaluateTrigger(trigger, triggerAssociation, object, referenceObjectUuid, data, eventHistory, null);
    }

    TriggerHistory evaluateTrigger(Trigger trigger, TriggerAssociation triggerAssociation, T object, UUID referenceObjectUuid, Object data, EventHistory eventHistory, List<RequestAttribute> pendingCustomAttributes) throws RuleException;

    /**
     * Method to evaluate a list of Rules on an Object
     *
     * @param triggerHistory Trigger History to fill rules evaluation results records for
     * @param rules    List of the Rules
     * @param object   Object to evaluate Rules on
     * @return True if all the rules are satisfied, false otherwise
     */
    default boolean evaluateRules(TriggerHistory triggerHistory, Set<Rule> rules, T object) throws RuleException {
        return evaluateRules(triggerHistory, rules, object, null);
    }

    boolean evaluateRules(TriggerHistory triggerHistory, Set<Rule> rules, T object, List<RequestAttribute> pendingCustomAttributes) throws RuleException;

    /**
     * Method to evaluate an Internal Rule on an Object
     *
     * @param internalRule Internal Rule to be evaluated
     * @param object   Object to evaluate Internal Rule on
     * @return True if the Internal Rule is satisfied, false otherwise
     */
    boolean evaluateInternalRule(ComplianceInternalRule internalRule, T object) throws RuleException;

    /**
     * Method to evaluate a Condition item on an Object
     *
     * @param conditionItem    Condition item to be evaluated
     * @param object   Object to evaluate conditionItem on
     * @return True if the condition item is satisfied, false otherwise
     */
    default boolean evaluateConditionItem(ConditionItem conditionItem, T object, Resource resource) throws RuleException {
        return evaluateConditionItem(conditionItem, object, resource, null);
    }

    boolean evaluateConditionItem(ConditionItem conditionItem, T object, Resource resource, List<RequestAttribute> pendingCustomAttributes) throws RuleException;

    /**
     * Method to perform Actions and Action Groups in a Trigger on an Object
     *
     * @param trigger        Trigger
     * @param triggerHistory Trigger History to fill action results records for
     * @param object         Object to perform Actions in Trigger on
     * @param data           Data associated with event associated with trigger
     */
    void performActions(Trigger trigger, TriggerHistory triggerHistory, T object, Object data) throws RuleException;

}
