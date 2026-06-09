package com.czertainly.core.events.handlers;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.evaluator.CertificateTriggerEvaluator;
import com.czertainly.core.events.data.EventDataBuilder;
import com.czertainly.core.messaging.model.EventMessage;
import org.springframework.stereotype.Component;

import java.util.UUID;

@SuppressWarnings("java:S6830")
@Component(ResourceEvent.Codes.CERTIFICATE_EXPIRING)
public class CertificateExpiringEventHandler extends CertificateEventsHandler {

    protected CertificateExpiringEventHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected Object getEventData(Certificate object, Object eventMessageData) {
        return EventDataBuilder.getCertificateExpiringEventData(object);
    }

    public static EventMessage constructEventMessages(UUID expiringCertificateUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, expiringCertificateUuid, null);
    }
}
