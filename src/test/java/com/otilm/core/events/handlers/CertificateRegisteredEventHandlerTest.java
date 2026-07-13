package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertificateRegisteredEventHandlerTest {

    private final CertificateRegistrationAuthorizationRepository authorizationRepository =
            mock(CertificateRegistrationAuthorizationRepository.class);
    private final RegistrationChallengeStore challengeStore = mock(RegistrationChallengeStore.class);
    private final CertificateRegisteredEventHandler handler = new CertificateRegisteredEventHandler(
            mock(CertificateRepository.class), mock(CertificateTriggerEvaluator.class), challengeStore, authorizationRepository);

    @Test
    void getEventDataResolvesCredentialAndDeadlineAndKeepsCredentialOutOfToString() {
        UUID certUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certUuid);
        certificate.setSubjectDn("CN=device-7");

        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(certUuid);
        authorization.setExpiresAt(OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        when(authorizationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.of(authorization));
        when(challengeStore.resolvePlaintext(authorization)).thenReturn("s3cret-challenge");

        CertificateRegisteredEventData data = (CertificateRegisteredEventData) handler.getEventData(certificate, null);

        assertEquals("s3cret-challenge", data.getCredential(), "credential is recovered for external delivery");
        assertNotNull(data.getCompletionDeadline(), "completion deadline comes from the authorization");
        assertEquals("CN=device-7", data.getSubjectDn());
        assertFalse(data.toString().contains("s3cret-challenge"), "credential must not leak via the event-data toString");
    }

    @Test
    void getEventDataWithoutAuthorizationLeavesCredentialNull() {
        UUID certUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certUuid);
        when(authorizationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());

        CertificateRegisteredEventData data = (CertificateRegisteredEventData) handler.getEventData(certificate, null);

        assertNull(data.getCredential());
        assertNull(data.getCompletionDeadline());
    }

    @Test
    void sendFollowUpPublishesOwnerOnlyInternalNotificationWithoutCredential() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        handler.setApplicationEventPublisher(publisher);

        UUID certUuid = UUID.randomUUID();
        UUID ownerUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certUuid);
        certificate.setSubjectDn("CN=device-7");
        OwnerAssociation owner = new OwnerAssociation();
        owner.setUuid(ownerUuid);
        certificate.setOwner(owner);

        CertificateRegisteredEventData full = new CertificateRegisteredEventData();
        full.setSubjectDn("CN=device-7");
        full.setCompletionDeadline(ZonedDateTime.parse("2026-08-01T00:00:00Z"));
        full.setCredential("s3cret-challenge");

        EventMessage eventMessage = new EventMessage(ResourceEvent.CERTIFICATE_REGISTERED, Resource.CERTIFICATE, certUuid, null);
        EventContext<Certificate> ctx = new EventContext<>(eventMessage, mock(CertificateTriggerEvaluator.class), certificate, full);

        handler.sendFollowUpEventsNotifications(ctx);

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        NotificationMessage msg = captor.getValue();
        assertNull(msg.getNotificationProfileUuids(), "default notification is internal (no profile)");
        assertEquals(1, msg.getRecipients().size(), "owner-only recipient (no groups)");
        assertEquals(RecipientType.USER, msg.getRecipients().get(0).getRecipientType());
        assertEquals(ownerUuid, msg.getRecipients().get(0).getRecipientUuid());
        CertificateRegisteredEventData internal = (CertificateRegisteredEventData) msg.getData();
        assertNull(internal.getCredential(), "the internal message must not carry the credential");
        assertEquals("CN=device-7", internal.getSubjectDn(), "identity is preserved for the internal notification");
    }
}
