package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.events.data.CertificateNotCompliantEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.evaluator.CertificateTriggerEvaluator;
import com.czertainly.core.events.data.EventDataBuilder;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.service.ComplianceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@SuppressWarnings("java:S6830")
@Component(ResourceEvent.Codes.CERTIFICATE_NOT_COMPLIANT)
public class CertificateNotCompliantEventHandler extends CertificateEventsHandler {

    private ComplianceExternalService complianceService;

    @Autowired
    public void setComplianceService(ComplianceExternalService complianceService) {
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
