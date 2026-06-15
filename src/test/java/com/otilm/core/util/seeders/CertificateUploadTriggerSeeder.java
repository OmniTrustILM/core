package com.otilm.core.util.seeders;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.RuleDetailDto;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerDetailDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.enums.FilterField;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Seeds an "ignore" trigger on the {@code CERTIFICATE_UPLOADED} event whose single condition matches an
 * ISSUED certificate, then associates it globally. With this trigger in place {@code uploadSync} of an
 * issued certificate is suppressed, so the upload is recorded as "not uploaded".
 * <p>
 * The condition → rule → trigger → association chain is created through the real {@code RuleExternalService}
 * and {@code TriggerExternalService}, the same path operators use, so tests exercise the genuine workflow
 * wiring rather than a hand-built shortcut.
 */
@Component
public class CertificateUploadTriggerSeeder {

    @Autowired
    private RuleExternalService ruleService;

    @Autowired
    private TriggerExternalService triggerService;

    /** Creates and globally associates an ignore trigger for uploads of ISSUED certificates. */
    public void seedIgnoreTrigger() throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItem = new ConditionItemRequestDto();
        conditionItem.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItem.setFieldIdentifier(FilterField.CERTIFICATE_STATE.name());
        conditionItem.setOperator(FilterConditionOperator.EQUALS);
        conditionItem.setValue(List.of(CertificateState.ISSUED.getCode()));

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

        triggerService.createTriggerAssociations(ResourceEvent.CERTIFICATE_UPLOADED, null, null,
                List.of(UUID.fromString(trigger.getUuid())), true);
    }
}
