package com.otilm.core.integration.events;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.common.events.data.CertificateStatusChangedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.notifications.Notification;
import com.otilm.core.dao.repository.notifications.NotificationRepository;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Covers the transaction half of internal notification delivery, which a mocked unit test cannot reach: the listener
 * bean here is the real proxy, so {@code REQUIRES_NEW} genuinely suspends the shared transaction. Extends
 * {@link BaseSpringBootTest}, which is deliberately not {@code @Transactional} -- a test-managed rollback would hide
 * exactly the behaviour being asserted.
 */
class NotificationInternalNotificationITest extends BaseSpringBootTest {

    private static final UUID EMPTY_GROUP_UUID = UUID.randomUUID();
    private static final UUID BROKEN_ROLE_UUID = UUID.randomUUID();

    @Autowired
    private NotificationListener notificationListener;
    @Autowired
    private NotificationRepository notificationRepository;

    private WireMockServer mockServer;

    @BeforeEach
    void startAuthServiceMock() {
        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", WireMockPorts.AUTH_SERVICE);

        // The one existing user belongs to no group, so any group recipient resolves to nobody
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users")).willReturn(WireMock.okJson("""
                {
                    "data": [
                        {
                            "uuid": "%s",
                            "username": "unaffiliated",
                            "email": "unaffiliated@example.com",
                            "enabled": true,
                            "systemUser": false,
                            "groups": []
                        }
                    ]
                }
                """.formatted(UUID.randomUUID()))));
    }

    private static NotificationMessage statusChangedMessage(UUID certificateUuid,
            List<NotificationRecipient> recipients) {
        CertificateStatusChangedEventData data = new CertificateStatusChangedEventData();
        data.setOldStatus("Not checked");
        data.setNewStatus("Valid");
        data.setSubjectDn("CN=device-7");
        data.setSerialNumber("18000102cf23da6a86e8");
        data.setIssuerDn("CN=Demo Sub CA");

        return new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificateUuid,
                null, recipients, data);
    }

    @AfterEach
    void stopAuthServiceMock() {
        mockServer.stop();
    }

    /**
     * The regression this guards: a memberless group used to throw, marking the shared transaction rollback-only past
     * the listener's own catch, so the notification created for the preceding recipient was discarded at commit and the
     * message failed with UnexpectedRollbackException.
     */
    @Test
    void memberlessGroupCostsNeitherThePrecedingNorTheFollowingRecipientTheirNotification() {
        UUID certificateUuid = UUID.randomUUID();
        // The memberless group sits between two users: the first proves an earlier notification survives the
        // failure, the second proves the loop carries on past it.
        NotificationMessage message = statusChangedMessage(certificateUuid,
                List
                        .of(new NotificationRecipient(RecipientType.USER, UUID.randomUUID()),
                                new NotificationRecipient(RecipientType.GROUP, EMPTY_GROUP_UUID),
                                new NotificationRecipient(RecipientType.USER, UUID.randomUUID())));

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        List<Notification> notifications = notificationRepository.findAll();
        Assertions
                .assertEquals(2, notifications.size(),
                        "both users are notified despite the memberless group between them");
        Assertions
                .assertTrue(
                        notifications
                                .stream()
                                .allMatch(n -> certificateUuid.toString().equals(n.getTargetObjectIdentification())),
                        "each notification targets the certificate the event was raised for");
    }

    /**
     * The memberless-group case no longer throws, so on its own it cannot prove the isolation: only a recipient that
     * genuinely fails inside a transactional collaborator does. The auth service returns a malformed user UUID for this
     * role, so {@code createNotificationForUsers} raises an unchecked exception from inside its own
     * {@code @Transactional} boundary -- which, without a transaction of its own, marks the listener's transaction
     * rollback-only and takes both users' notifications down with it at commit.
     */
    @Test
    void recipientFailingInsideATransactionalCollaboratorIsIsolatedFromTheOthers() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/roles/" + BROKEN_ROLE_UUID + "/users"))
                        .willReturn(WireMock
                                .okJson("""
                                        [{"uuid": "not-a-uuid", "username": "broken", "enabled": true, "systemUser": false, "groups": []}]
                                        """)));

        NotificationMessage message = statusChangedMessage(UUID.randomUUID(),
                List
                        .of(new NotificationRecipient(RecipientType.USER, UUID.randomUUID()),
                                new NotificationRecipient(RecipientType.ROLE, BROKEN_ROLE_UUID),
                                new NotificationRecipient(RecipientType.USER, UUID.randomUUID())));

        Assertions
                .assertDoesNotThrow(() -> notificationListener.processMessage(message),
                        "the failing recipient must not surface as UnexpectedRollbackException on commit");

        Assertions
                .assertEquals(2, notificationRepository.findAll().size(),
                        "both users keep their notification despite the recipient that failed between them");
    }

    @Test
    void allRecipientsResolvingToNobodyCreatesNoNotification() {
        NotificationMessage message = statusChangedMessage(UUID.randomUUID(),
                List.of(new NotificationRecipient(RecipientType.GROUP, EMPTY_GROUP_UUID)));

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        Assertions
                .assertTrue(notificationRepository.findAll().isEmpty(),
                        "a group with no members notifies no one rather than creating an unaddressed notification");
    }
}
