package com.otilm.core.util.seeders;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ActionRequestDto;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.RuleDetailDto;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerDetailDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.enums.FilterField;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Seeds an "ignore" trigger on the {@code CERTIFICATE_UPLOADED} event whose single condition matches an ISSUED
 * certificate, then associates it globally. With this trigger in place {@code uploadSync} of an issued certificate is
 * suppressed, so the upload is recorded as "not uploaded".
 * <p>
 * The condition → rule → trigger → association chain is created through the real {@code RuleExternalService} and
 * {@code TriggerExternalService}, the same path operators use, so tests exercise the genuine workflow wiring rather
 * than a hand-built shortcut.
 */
@Component
public class CertificateUploadTriggerSeeder {

    @Autowired
    private RuleExternalService ruleService;

    @Autowired
    private TriggerExternalService triggerService;

    @Autowired
    private ActionExternalService actionService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /** Creates and globally associates an ignore trigger for uploads of ISSUED certificates. */
    public void seedIgnoreTrigger() throws AlreadyExistException, NotFoundException {
        seedIgnoreTrigger(FilterField.CERTIFICATE_STATE, List.of(CertificateState.ISSUED.getCode()));
    }

    /**
     * Creates and globally associates an ignore trigger for uploads of certificates whose field equals the value: a
     * string for a string field, a list of codes for a list field.
     */
    public void seedIgnoreTrigger(FilterField field, Object value) throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItem = new ConditionItemRequestDto();
        conditionItem.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItem.setFieldIdentifier(field.name());
        conditionItem.setOperator(FilterConditionOperator.EQUALS);
        conditionItem.setValue(value);

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("IgnoreUploadCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItem));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("IgnoreUploadRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("IgnoreUploadTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_UPLOADED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of());
        triggerRequest.setIgnoreTrigger(true);
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null,
                        List.of(UUID.fromString(trigger.getUuid())), true);
    }

    /** Creates and globally associates a trigger that sets the owner of an uploaded ISSUED certificate to the user. */
    public void seedSetOwnerTrigger(UUID ownerUuid) throws AlreadyExistException, NotFoundException {
        seedOwnerTrigger(ownerUuid, CertificateState.ISSUED, OwnerTriggerFault.NONE);
    }

    /** Creates and globally associates a trigger that clears the owner of an uploaded ISSUED certificate. */
    public void seedClearOwnerTrigger() throws AlreadyExistException, NotFoundException {
        seedOwnerTrigger(null, CertificateState.ISSUED, OwnerTriggerFault.NONE);
    }

    /** As {@link #seedClearOwnerTrigger()}, with a second execution in the action that the evaluator refuses. */
    public void seedClearOwnerTriggerWithFailingExecution() throws AlreadyExistException, NotFoundException {
        seedOwnerTrigger(null, CertificateState.ISSUED, OwnerTriggerFault.FAILING_EXECUTION);
    }

    /** As {@link #seedClearOwnerTrigger()}, with a second item in the same execution that the evaluator refuses. */
    public void seedClearOwnerTriggerWithFailingItem() throws AlreadyExistException, NotFoundException {
        seedOwnerTrigger(null, CertificateState.ISSUED, OwnerTriggerFault.FAILING_ITEM);
    }

    /** As {@link #seedClearOwnerTrigger()}, with a condition that an uploaded ISSUED certificate does not meet. */
    public void seedClearOwnerTriggerThatDoesNotMatch() throws AlreadyExistException, NotFoundException {
        seedOwnerTrigger(null, CertificateState.REVOKED, OwnerTriggerFault.NONE);
    }

    private void seedOwnerTrigger(UUID ownerUuid, CertificateState matchedState, OwnerTriggerFault fault)
            throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItem = new ConditionItemRequestDto();
        conditionItem.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItem.setFieldIdentifier(FilterField.CERTIFICATE_STATE.name());
        conditionItem.setOperator(FilterConditionOperator.EQUALS);
        conditionItem.setValue(List.of(matchedState.getCode()));
        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("OwnerUploadCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItem));
        String conditionUuid = ruleService.createCondition(conditionRequest).getUuid();

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("OwnerUploadRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(conditionUuid));
        String ruleUuid = ruleService.createRule(ruleRequest).getUuid();

        ExecutionItemRequestDto ownerItem = new ExecutionItemRequestDto();
        ownerItem.setFieldSource(FilterFieldSource.PROPERTY);
        ownerItem.setFieldIdentifier(FilterField.OWNER.toString());
        ownerItem.setData(ownerUuid == null ? null : ownerUuid.toString());
        List<ExecutionItemRequestDto> ownerExecutionItems = fault == OwnerTriggerFault.FAILING_ITEM
                ? List.of(ownerItem, notAGroupItem())
                : List.of(ownerItem);
        List<String> executionUuids = new ArrayList<>(
                List.of(createExecution("OwnerUploadExecution", ownerExecutionItems)));
        if (fault == OwnerTriggerFault.FAILING_EXECUTION) {
            executionUuids.add(createExecution("FailingUploadExecution", List.of(notAGroupItem())));
        }

        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("OwnerUploadAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(executionUuids);
        String actionUuid = actionService.createAction(actionRequest).getUuid();

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("OwnerUploadTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_UPLOADED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(ruleUuid));
        triggerRequest.setActionsUuids(List.of(actionUuid));
        triggerRequest.setIgnoreTrigger(false);
        String triggerUuid = triggerService.createTrigger(triggerRequest).getUuid();

        triggerService
                .createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null,
                        List.of(UUID.fromString(triggerUuid)), true);
    }

    private String createExecution(String name, List<ExecutionItemRequestDto> items)
            throws AlreadyExistException, NotFoundException {
        ExecutionRequestDto request = new ExecutionRequestDto();
        request.setName(name);
        request.setResource(Resource.CERTIFICATE);
        request.setType(ExecutionType.SET_FIELD);
        request.setItems(items);
        return actionService.createExecution(request).getUuid();
    }

    /** An item the evaluator refuses: a group that is not a UUID. */
    private static ExecutionItemRequestDto notAGroupItem() {
        ExecutionItemRequestDto item = new ExecutionItemRequestDto();
        item.setFieldSource(FilterFieldSource.PROPERTY);
        item.setFieldIdentifier(FilterField.GROUP_NAME.toString());
        item.setData("not-a-uuid");
        return item;
    }

    private enum OwnerTriggerFault {
        NONE,
        FAILING_EXECUTION,
        FAILING_ITEM
    }

    /**
     * Removes the global associations of the upload triggers, so uploads are no longer ignored. The history of the
     * triggers that fired is detached first, as the migrated schema's foreign key does and the tests' schema does not.
     */
    public void removeIgnoreTriggers() throws NotFoundException {
        jdbcTemplate.update("UPDATE trigger_history SET trigger_association_uuid = NULL");
        triggerService.createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null, List.of(), true);
    }
}
