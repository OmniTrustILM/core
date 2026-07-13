package com.otilm.core.messaging.jms.listeners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.NotificationInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class NotificationListenerTest {

    private final NotificationInternalService notificationService = mock(NotificationInternalService.class);

    private NotificationListener listener() {
        ObjectMapper realMapper = JsonMapper.builder().findAndAddModules().build();
        return new NotificationListener(
                realMapper,
                mock(AttributeEngine.class),
                notificationService,
                mock(TriggerInternalService.class),
                mock(ConnectorApiFactory.class),
                mock(ConnectorInternalService.class),
                mock(PendingNotificationRepository.class),
                mock(NotificationProfileVersionRepository.class),
                mock(NotificationInstanceReferenceRepository.class),
                mock(GroupRepository.class),
                mock(UserManagementApiClient.class),
                mock(RoleManagementApiClient.class),
                mock(ResourceObjectAssociationService.class));
    }

    @Test
    void certificateRegisteredInternalNotificationDescribesTheCertWithoutTheCredential() {
        UUID certUuid = UUID.randomUUID();
        UUID ownerUuid = UUID.randomUUID();
        CertificateRegisteredEventData data = new CertificateRegisteredEventData();
        data.setSubjectDn("CN=device-7");
        data.setCompletionDeadline(ZonedDateTime.parse("2026-08-01T00:00:00Z"));
        data.setCredential("s3cret-challenge-value");

        // Default internal path: profileUuids == null, an owner USER recipient.
        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_REGISTERED, Resource.CERTIFICATE, certUuid, null,
                List.of(new NotificationRecipient(RecipientType.USER, ownerUuid)), data);

        listener().processMessage(message);

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
        verify(notificationService).createNotificationForUser(text.capture(), detail.capture(),
                eq(ownerUuid.toString()), eq(Resource.CERTIFICATE), eq(certUuid.toString()));

        assertTrue(text.getValue().contains("CN=device-7"), "the internal notification names the certificate");
        assertFalse((text.getValue() + detail.getValue()).contains("s3cret-challenge-value"),
                "the credential must never be written into the persisted internal notification");
    }
}
