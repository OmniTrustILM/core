package com.otilm.core.messaging.jms.listeners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.otilm.api.interfaces.client.v1.NotificationInstanceSyncApiClient;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.NotificationInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.notifications.NotificationObjectDataService;
import com.otilm.core.service.notifications.NotificationSubjectResolver.SubjectRef;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.service.writer.PendingNotificationWriter;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class NotificationListenerTest {

    private final NotificationInternalService notificationService = mock(NotificationInternalService.class);

    private final ResourceObjectAssociationService associationService = mock(ResourceObjectAssociationService.class);

    private NotificationListener listener() {
        ObjectMapper realMapper = JsonMapper.builder().findAndAddModules().build();
        return new NotificationListener(realMapper, mock(AttributeEngine.class), notificationService,
                mock(TriggerInternalService.class), mock(ConnectorApiFactory.class),
                mock(ConnectorInternalService.class), mock(PendingNotificationRepository.class),
                mock(NotificationProfileVersionRepository.class), mock(NotificationInstanceReferenceRepository.class),
                mock(GroupRepository.class), mock(UserManagementApiClient.class), mock(RoleManagementApiClient.class),
                associationService,
                // The real handler, invoked directly rather than through its proxy, runs the work without a
                // transaction -- which is what this unencumbered unit context wants.
                new TransactionHandler(), mock(PendingNotificationWriter.class),
                mock(NotificationObjectDataService.class));
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
        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_REGISTERED,
                Resource.CERTIFICATE, certUuid, null, List.of(new NotificationRecipient(RecipientType.USER, ownerUuid)),
                data);

        listener().processMessage(message);

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
        verify(notificationService)
                .createNotificationForUser(text.capture(), detail.capture(), eq(ownerUuid.toString()),
                        eq(Resource.CERTIFICATE), eq(certUuid.toString()));

        assertTrue(text.getValue().contains("CN=device-7"), "the internal notification names the certificate");
        assertFalse((text.getValue() + detail.getValue()).contains("s3cret-challenge-value"),
                "the credential must never be written into the persisted internal notification");
    }

    @Test
    void connectorAcceptedSendSurvivesFailedSuppressionWrite() throws Exception {
        // The connector accepted the notification; the suppression-state write then fails. The
        // failure must be logged and swallowed: reporting it as a delivery failure (trigger
        // history) would misstate a delivery that already happened, and letting it escape would
        // trigger a redelivery and a duplicate send.
        UUID profileUuid = UUID.randomUUID();
        UUID instanceRefUuid = UUID.randomUUID();

        NotificationProfileVersion version = new NotificationProfileVersion();
        version.setNotificationProfileUuid(profileUuid);
        version.setVersion(1);
        version.setRecipientType(RecipientType.NONE);
        version.setInternalNotification(false);
        version.setRepetitions(5);
        version.setNotificationInstanceRefUuid(instanceRefUuid);

        NotificationInstanceReference instanceRef = new NotificationInstanceReference();
        instanceRef.setKind("WEBHOOK");
        instanceRef.setConnectorUuid(UUID.randomUUID());
        instanceRef.setNotificationInstanceUuid(UUID.randomUUID());
        instanceRef.setMappedAttributes(List.of());

        NotificationProfileVersionRepository versionRepository = mock(NotificationProfileVersionRepository.class);
        when(versionRepository.findTopByNotificationProfileUuidOrderByVersionDesc(profileUuid))
                .thenReturn(Optional.of(version));
        NotificationInstanceReferenceRepository instanceRefRepository = mock(
                NotificationInstanceReferenceRepository.class);
        when(instanceRefRepository.findWithMappedAttributesByUuid(instanceRefUuid))
                .thenReturn(Optional.of(instanceRef));

        ConnectorInternalService connectorService = mock(ConnectorInternalService.class);
        NotificationInstanceSyncApiClient apiClient = mock(NotificationInstanceSyncApiClient.class);
        when(apiClient.listMappingAttributes(any(), any())).thenReturn(List.of());
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        when(connectorApiFactory.getNotificationInstanceApiClient(any())).thenReturn(apiClient);

        PendingNotificationWriter failingWriter = mock(PendingNotificationWriter.class);
        doThrow(new RuntimeException("suppression store unavailable"))
                .when(failingWriter)
                .recordSent(any(), any(), any(), any(), anyInt());
        TriggerInternalService triggerService = mock(TriggerInternalService.class);

        NotificationListener listener = new NotificationListener(JsonMapper.builder().findAndAddModules().build(),
                mock(AttributeEngine.class), notificationService, triggerService, connectorApiFactory, connectorService,
                mock(PendingNotificationRepository.class), versionRepository, instanceRefRepository,
                mock(GroupRepository.class), mock(UserManagementApiClient.class), mock(RoleManagementApiClient.class),
                mock(ResourceObjectAssociationService.class), new TransactionHandler(), failingWriter,
                mock(NotificationObjectDataService.class));

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE,
                UUID.randomUUID(), List.of(profileUuid), List.of(), null, UUID.randomUUID(), null);

        assertDoesNotThrow(() -> listener.processMessage(message));

        verify(apiClient).sendNotification(any(), any(), any());
        verify(failingWriter)
                .recordSent(eq(profileUuid), eq(Resource.CERTIFICATE), any(), eq(ResourceEvent.CERTIFICATE_EXPIRING),
                        eq(1));
        // The failed suppression write is not a delivery failure: trigger history stays untouched.
        verifyNoInteractions(triggerService);
    }

    @Test
    void defaultRecipientsForCommentEventsResolveToTheHostOwnerAndGroups() {
        UUID hostUuid = UUID.randomUUID();
        UUID ownerUuid = UUID.randomUUID();
        UUID groupUuid = UUID.randomUUID();
        when(associationService.getOwner(Resource.RA_PROFILE, hostUuid))
                .thenReturn(new NameAndUuidDto(ownerUuid.toString(), "tst-owner"));
        when(associationService.getGroupUuids(Resource.RA_PROFILE, hostUuid)).thenReturn(List.of(groupUuid));

        List<NotificationRecipient> recipients = listener()
                .getDefaultRecipients(ResourceEvent.COMMENT_CREATED, null, Resource.RA_PROFILE, hostUuid);

        assertEquals(2, recipients.size());
        assertEquals(RecipientType.USER, recipients.get(0).getRecipientType());
        assertEquals(ownerUuid, recipients.get(0).getRecipientUuid());
        assertEquals(RecipientType.GROUP, recipients.get(1).getRecipientType());
        assertEquals(groupUuid, recipients.get(1).getRecipientUuid());
    }

    @Test
    void commentNotificationsPointAtTheHostWhileEveryOtherEventKeepsItsOwnRecord() {
        UUID approvalUuid = UUID.randomUUID();
        UUID hostUuid = UUID.randomUUID();
        SubjectRef approvalTarget = new SubjectRef(Resource.CERTIFICATE, UUID.randomUUID());
        SubjectRef commentHost = new SubjectRef(Resource.RA_PROFILE, hostUuid);

        // An approval notification has to open the approval, not the object awaiting it
        assertEquals(new SubjectRef(Resource.APPROVAL, approvalUuid),
                NotificationListener
                        .internalNotificationTarget(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL, approvalUuid,
                                approvalTarget));
        // A comment has no page of its own, so its notification opens the host thread
        assertEquals(commentHost,
                NotificationListener
                        .internalNotificationTarget(ResourceEvent.COMMENT_CREATED, Resource.COMMENT, UUID.randomUUID(),
                                commentHost));
        assertEquals(commentHost,
                NotificationListener
                        .internalNotificationTarget(ResourceEvent.COMMENT_RESOLVED, Resource.COMMENT, UUID.randomUUID(),
                                commentHost));
    }

    @Test
    void explicitRecipientsYieldsNoneWhenUuidListMissing() {
        // A profile configured with an explicit recipient type but no UUIDs must not dereference the null list.
        assertTrue(NotificationListener.explicitRecipients(RecipientType.GROUP, null).isEmpty(),
                "a null recipient UUID list yields no recipients instead of throwing");
        assertTrue(NotificationListener.explicitRecipients(RecipientType.USER, List.of()).isEmpty(),
                "an empty recipient UUID list yields no recipients");
    }

    @Test
    void explicitRecipientsMapsEachConfiguredUuid() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();

        List<NotificationRecipient> mapped = NotificationListener
                .explicitRecipients(RecipientType.ROLE, List.of(first, second));

        assertEquals(2, mapped.size());
        assertEquals(RecipientType.ROLE, mapped.get(0).getRecipientType());
        assertEquals(first, mapped.get(0).getRecipientUuid());
        assertEquals(second, mapped.get(1).getRecipientUuid());
    }

    private CommentEventData commentEventData(UUID parentUuid, String body) {
        CommentEventData data = new CommentEventData();
        data.setCommentUuid(UUID.randomUUID());
        data.setParentUuid(parentUuid);
        data.setResource(Resource.RA_PROFILE);
        data.setObjectUuid(UUID.randomUUID());
        data.setObjectName("web-frontends");
        data.setAuthorUuid(UUID.randomUUID());
        data.setAuthorUsername("requester");
        data.setCreatedAt(OffsetDateTime.now());
        data.setBody(body);
        return data;
    }

    private String[] renderedCommentNotification(ResourceEvent event, CommentEventData data) {
        UUID recipientUuid = UUID.randomUUID();
        NotificationMessage message = new NotificationMessage(event, data.getResource(), data.getObjectUuid(), null,
                List.of(new NotificationRecipient(RecipientType.USER, recipientUuid)), data);

        listener().processMessage(message);

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
        verify(notificationService)
                .createNotificationForUser(text.capture(), detail.capture(), eq(recipientUuid.toString()),
                        eq(data.getResource()), eq(data.getObjectUuid().toString()));
        return new String[]{text.getValue(), detail.getValue()};
    }

    @Test
    void rootCommentRendersTheAuthorActingOnTheHostObject() {
        String[] rendered = renderedCommentNotification(ResourceEvent.COMMENT_CREATED,
                commentEventData(null, "please **enable** ACME"));

        assertEquals("requester commented on RA Profile 'web-frontends'", rendered[0]);
        assertNull(rendered[1], "the persisted notification carries no comment body");
    }

    @Test
    void replyRendersAsAThreadReply() {
        String[] rendered = renderedCommentNotification(ResourceEvent.COMMENT_CREATED,
                commentEventData(UUID.randomUUID(), "on it"));

        assertEquals("requester replied to a comment thread on RA Profile 'web-frontends'", rendered[0]);
    }

    @Test
    void resolutionRendersTheActingUserAndDirection() {
        CommentEventData resolved = commentEventData(null, "done");
        resolved.setResolved(true);
        resolved.setResolvedByUuid(UUID.randomUUID());
        resolved.setResolvedByUsername("operator");

        assertEquals("operator resolved a comment thread on RA Profile 'web-frontends'",
                renderedCommentNotification(ResourceEvent.COMMENT_RESOLVED, resolved)[0]);
    }

    @Test
    void reopeningRendersTheActingUserAndDirection() {
        CommentEventData reopened = commentEventData(null, "not done after all");
        reopened.setResolved(false);
        reopened.setResolvedByUuid(UUID.randomUUID());
        reopened.setResolvedByUsername("operator");

        assertEquals("operator reopened a comment thread on RA Profile 'web-frontends'",
                renderedCommentNotification(ResourceEvent.COMMENT_RESOLVED, reopened)[0]);
    }

}
