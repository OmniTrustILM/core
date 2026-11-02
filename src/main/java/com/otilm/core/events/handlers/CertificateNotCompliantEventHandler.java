package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
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
import com.otilm.core.service.writer.PendingNotificationWriter;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@SuppressWarnings("java:S6830")
@Component(ResourceEvent.Codes.CERTIFICATE_NOT_COMPLIANT)
public class CertificateNotCompliantEventHandler extends CertificateEventsHandler {

    private static final String REMINDER_DATA = "reminder";

    private ComplianceInternalService complianceService;
    private PendingNotificationWriter pendingNotificationWriter;

    @Autowired
    public void setComplianceService(ComplianceInternalService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setPendingNotificationWriter(PendingNotificationWriter pendingNotificationWriter) {
        this.pendingNotificationWriter = pendingNotificationWriter;
    }

    protected CertificateNotCompliantEventHandler(CertificateRepository repository,
            CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    public static EventMessage constructEventMessages(UUID objectUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_NOT_COMPLIANT, Resource.CERTIFICATE, objectUuid, null);
    }

    public static EventMessage constructReminderEventMessage(UUID objectUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_NOT_COMPLIANT, Resource.CERTIFICATE, objectUuid,
                REMINDER_DATA);
    }

    @Override
    public void handleEvent(EventMessage eventMessage) throws EventException {
        if (!REMINDER_DATA.equals(eventMessage.getData())) {
            pendingNotificationWriter
                    .deleteForObjectAndEvent(Resource.CERTIFICATE, eventMessage.getObjectUuid(),
                            ResourceEvent.CERTIFICATE_NOT_COMPLIANT);
        }
        super.handleEvent(eventMessage);
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
