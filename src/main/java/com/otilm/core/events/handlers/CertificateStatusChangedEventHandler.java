package com.otilm.core.events.handlers;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.events.transaction.UpdateCertificateHistoryEvent;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Transactional
@Component(ResourceEvent.Codes.CERTIFICATE_STATUS_CHANGED)
public class CertificateStatusChangedEventHandler extends CertificateEventsHandler {

    protected CertificateStatusChangedEventHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected Object getEventData(Certificate certificate, Object eventMessageData) {
        CertificateValidationStatus[] statusArrayData = objectMapper.convertValue(eventMessageData, new TypeReference<>() {});

        return EventDataBuilder.getCertificateStatusChangedEventData(certificate, statusArrayData);
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Certificate> eventContext) {
        Certificate certificate = eventContext.getResourceObjects().getFirst();
        Object eventData = eventContext.getResourceObjectsEventData().getFirst();
        CertificateValidationStatus[] statusArrayData = objectMapper.convertValue(eventContext.getData(), new TypeReference<>() {});

        List<NotificationRecipient> recipients = NotificationRecipient.buildUsersAndGroupsNotificationRecipients(certificate.getOwner() == null ? null : List.of(certificate.getOwner().getUuid()), certificate.getGroups() == null ? null : certificate.getGroups().stream().map(UniquelyIdentifiedAndAudited::getUuid).toList());
        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.CERTIFICATE, certificate.getUuid(), null, recipients, eventData);
        applicationEventPublisher.publishEvent(notificationMessage);

        // handle certificate event history record
        applicationEventPublisher.publishEvent(new UpdateCertificateHistoryEvent(certificate.getUuid(), CertificateEvent.UPDATE_VALIDATION_STATUS, CertificateEventStatus.SUCCESS, statusArrayData[0], statusArrayData[1]));
    }

    public static EventMessage constructEventMessage(UUID certificateUuid, CertificateValidationStatus oldStatus, CertificateValidationStatus newStatus) {
        CertificateValidationStatus[] statusArrayData = new CertificateValidationStatus[] { oldStatus, newStatus };
        return new EventMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificateUuid, statusArrayData);
    }

}
