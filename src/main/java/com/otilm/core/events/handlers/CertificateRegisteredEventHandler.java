package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Transactional
@Component(ResourceEvent.Codes.CERTIFICATE_REGISTERED)
public class CertificateRegisteredEventHandler extends CertificateEventsHandler {

    private final RegistrationChallengeStore registrationChallengeStore;
    private final CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;

    protected CertificateRegisteredEventHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator,
                                                RegistrationChallengeStore registrationChallengeStore,
                                                CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository) {
        super(repository, ruleEvaluator);
        this.registrationChallengeStore = registrationChallengeStore;
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
    }

    @Override
    protected Object getEventData(Certificate certificate, Object eventMessageData) {
        CertificateRegisteredEventData eventData = EventDataBuilder.getCertificateRegisteredEventData(certificate);
        // The issuance deadline and the plaintext credential come from the registration authorization; the
        // credential is recovered here (only this path decrypts it) and rides the event-data object to the
        // external provider. It is excluded from the event-data toString and from the internal notification text.
        registrationAuthorizationRepository.findByCertificateUuid(certificate.getUuid()).ifPresent(authorization -> {
            if (authorization.getExpiresAt() != null) {
                eventData.setIssuanceDeadline(authorization.getExpiresAt().toZonedDateTime());
            }
            eventData.setCredential(registrationChallengeStore.resolvePlaintext(authorization));
        });
        return eventData;
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Certificate> eventContext) {
        Certificate certificate = eventContext.getResourceObjects().getFirst();
        Object eventData = eventContext.getResourceObjectsEventData().getFirst();
        // Default recipient is the owner only (no groups) — a notification profile can override. The credential
        // is delivered only on the external-provider path; the internal notification is informational.
        List<NotificationRecipient> recipients = NotificationRecipient.buildUsersAndGroupsNotificationRecipients(
                certificate.getOwner() == null ? null : List.of(certificate.getOwner().getUuid()), null);
        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.CERTIFICATE, certificate.getUuid(), null, recipients, eventData);
        applicationEventPublisher.publishEvent(notificationMessage);
    }

    public static EventMessage constructEventMessage(UUID certificateUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_REGISTERED, Resource.CERTIFICATE, certificateUuid, null);
    }
}
