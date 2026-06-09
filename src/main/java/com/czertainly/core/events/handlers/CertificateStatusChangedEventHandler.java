package com.czertainly.core.events.handlers;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.evaluator.CertificateTriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.data.EventDataBuilder;
import com.czertainly.core.events.transaction.UpdateCertificateHistoryEvent;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
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
