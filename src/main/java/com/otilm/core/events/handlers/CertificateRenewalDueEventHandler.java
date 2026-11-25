package com.otilm.core.events.handlers;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.messaging.model.EventMessage;
import java.util.UUID;
import org.springframework.stereotype.Component;

@SuppressWarnings("java:S6830")
@Component(ResourceEvent.Codes.CERTIFICATE_RENEWAL_DUE)
public class CertificateRenewalDueEventHandler extends CertificateEventsHandler {

    protected CertificateRenewalDueEventHandler(CertificateRepository repository,
            CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected Object getEventData(Certificate object, Object eventMessageData) {
        return EventDataBuilder.getCertificateRenewalDueEventData(object);
    }

    public static EventMessage constructEventMessages(UUID renewalDueCertificateUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_RENEWAL_DUE, Resource.CERTIFICATE, renewalDueCertificateUuid,
                null);
    }
}
