package com.otilm.core.events.handlers;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.events.data.CertificateNotCompliantEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.service.ComplianceInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@SuppressWarnings("java:S6830")
@Component(ResourceEvent.Codes.CERTIFICATE_NOT_COMPLIANT)
public class CertificateNotCompliantEventHandler extends CertificateEventsHandler {

    private ComplianceInternalService complianceService;

    @Autowired
    public void setComplianceService(ComplianceInternalService complianceService) {
        this.complianceService = complianceService;
    }

    protected CertificateNotCompliantEventHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    public static EventMessage constructEventMessages(UUID objectUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_NOT_COMPLIANT, Resource.CERTIFICATE, objectUuid, null);
    }

    @Override
    protected CertificateNotCompliantEventData getEventData(Certificate object, Object eventMessageData) {
        ComplianceCheckResultDto complianceCheckResult;
        try {
            complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, object.getUuid());
        } catch (NotFoundException e) {
            complianceCheckResult = null;
        }
        return EventDataBuilder.getCertificateNotCompliantEventData(object, complianceCheckResult);
    }
}
