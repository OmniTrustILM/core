package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.api.model.client.notification.NotificationRequestDto;
import com.otilm.api.model.client.notification.NotificationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.notifications.NotificationRecipientRepository;
import com.otilm.core.model.notification.NotificationSubject;
import com.otilm.core.service.NotificationExternalService;
import com.otilm.core.service.NotificationInternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
@Rollback
class NotificationServiceITest extends BaseSpringBootTest {

    private static final String MOCK_ROLE_UUID = UUID.randomUUID().toString();
    private String mockUser1Uuid;
    private static final String MOCK_USER_2_UUID = UUID.randomUUID().toString();
    private static final String MOCK_USER_3_UUID = UUID.randomUUID().toString();
    private static final String MOCK_GROUP_1_UUID = UUID.randomUUID().toString();
    private static final String MOCK_GROUP_2_UUID = UUID.randomUUID().toString();

    private WireMockServer mockServer;

    @Autowired
    private NotificationExternalService notificationExternalService;

    @Autowired
    private NotificationInternalService notificationInternalService;

    @Autowired
    private NotificationRecipientRepository notificationRecipientRepository;

    @BeforeEach
    public void setUp() {
        var authInfo = AuthHelper.getUserIdentification();
        mockUser1Uuid = authInfo.getUuid();
    }

    @AfterEach
    public void tearDown() {
        if (mockServer != null) {
            mockServer.stop();
            mockServer = null;
        }
    }

    @Test
    void testNotificationsOperations() throws NotFoundException {
        setupAuthServiceMock();

        notificationInternalService
                .createNotificationForRole("TestMessage", null, MOCK_ROLE_UUID, Resource.DISCOVERY,
                        UUID.randomUUID().toString());
        notificationInternalService
                .createNotificationForGroup("TestMessage2", null, MOCK_GROUP_1_UUID, Resource.DISCOVERY,
                        "%s,%s".formatted(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        notificationInternalService
                .createNotificationForUser("TestMessage3", null, mockUser1Uuid, Resource.DISCOVERY,
                        UUID.randomUUID().toString());

        Assertions.assertEquals(6, notificationRecipientRepository.findAll().size());

        NotificationRequestDto notificationRequestDto = new NotificationRequestDto();
        notificationRequestDto.setItemsPerPage(10);
        notificationRequestDto.setPageNumber(1);
        NotificationResponseDto listingResponse = notificationExternalService.listNotifications(notificationRequestDto);

        Assertions.assertEquals(3, listingResponse.getItems().size());

        notificationExternalService.markNotificationAsRead(listingResponse.getItems().getFirst().getUuid().toString());

        notificationRequestDto.setUnread(true);
        listingResponse = notificationExternalService.listNotifications(notificationRequestDto);

        Assertions.assertEquals(2, listingResponse.getItems().size());

        notificationExternalService
                .bulkDeleteNotifications(notificationRecipientRepository
                        .findAll()
                        .stream()
                        .map(n -> n.getNotificationUuid().toString())
                        .toList());

        // all notifications that are present in DB are send to bulk delete, but deleted should be only those of logged
        // user
        Assertions.assertEquals(3, notificationRecipientRepository.findAll().size());
    }

    @Test
    void listedCommentNotificationsCarryTheirSubject() {
        String hostUuid = UUID.randomUUID().toString();
        String rootUuid = UUID.randomUUID().toString();
        String replyUuid = UUID.randomUUID().toString();
        notificationInternalService
                .createNotificationForUser("root", null, mockUser1Uuid, Resource.RA_PROFILE, hostUuid,
                        new NotificationSubject(Resource.COMMENT, rootUuid, null));
        notificationInternalService
                .createNotificationForUser("reply", null, mockUser1Uuid, Resource.RA_PROFILE, hostUuid,
                        new NotificationSubject(Resource.COMMENT, replyUuid, rootUuid));
        notificationInternalService
                .createNotificationForUser("plain", null, mockUser1Uuid, Resource.DISCOVERY, hostUuid);

        NotificationRequestDto request = new NotificationRequestDto();
        request.setItemsPerPage(10);
        request.setPageNumber(1);
        for (boolean unread : new boolean[]{false, true}) {
            request.setUnread(unread);
            List<NotificationDto> listed = notificationExternalService.listNotifications(request).getItems();

            assertThat(listed).hasSize(3);
            NotificationDto root = byMessage(listed, "root");
            assertThat(root.getSubjectObjectType()).isEqualTo(Resource.COMMENT);
            assertThat(root.getSubjectObjectIdentification()).isEqualTo(rootUuid);
            assertThat(root.getSubjectParentIdentification()).isNull();
            NotificationDto reply = byMessage(listed, "reply");
            assertThat(reply.getSubjectObjectType()).isEqualTo(Resource.COMMENT);
            assertThat(reply.getSubjectObjectIdentification()).isEqualTo(replyUuid);
            assertThat(reply.getSubjectParentIdentification()).isEqualTo(rootUuid);
            NotificationDto plain = byMessage(listed, "plain");
            assertThat(plain.getSubjectObjectType()).isNull();
            assertThat(plain.getSubjectObjectIdentification()).isNull();
            assertThat(plain.getSubjectParentIdentification()).isNull();
        }
    }

    private static NotificationDto byMessage(List<NotificationDto> notifications, String message) {
        return notifications.stream().filter(n -> message.equals(n.getMessage())).findFirst().orElseThrow();
    }

    private void setupAuthServiceMock() {
        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        String listUsersMockResponse = """
                [
                     {
                         "uuid": "%s",
                         "username": "doejohn",
                         "firstName": "John",
                         "lastName": "Doe",
                         "groups": [{
                                 "uuid": "%s",
                                 "name": "TestGroup1"
                             }, {
                                 "uuid": "%s",
                                 "name": "TestGroup2"
                             }
                         ],
                         "enabled": true,
                         "systemUser": false
                     }, {
                         "uuid": "%s",
                         "username": "doejane",
                         "firstName": "Jane",
                         "lastName": "Doe",
                         "email": "jane.doe@example.com",
                         "groups": [{
                                 "uuid": "%s",
                                 "name": "TestGroup1"
                             }
                         ],
                         "enabled": true,
                         "systemUser": false
                     }, {
                         "uuid": "%s",
                         "username": "doejr",
                         "firstName": "Jr",
                         "lastName": "Doe",
                         "email": "jr.doe@example.com",
                         "groups": [{
                                 "uuid": "%s",
                                 "name": "TestGroup2"
                             }
                         ],
                         "enabled": true,
                         "systemUser": false
                     }
                ]
                """
                .formatted(mockUser1Uuid, MOCK_GROUP_1_UUID, MOCK_GROUP_2_UUID, MOCK_USER_2_UUID, MOCK_GROUP_1_UUID,
                        MOCK_USER_3_UUID, MOCK_GROUP_2_UUID);

        String paginatedListUsersMockResponse = """
                {
                    "data": %s
                }
                """.formatted(listUsersMockResponse);

        String roleDetailMockResponse = """
                {
                  "uuid": "%s",
                  "name": "test-role",
                  "description": "Test role",
                  "systemRole": false,
                  "users": %s,
                  "customAttributes": []
                }
                """.formatted(MOCK_ROLE_UUID, listUsersMockResponse);

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/users"))
                        .willReturn(WireMock.okJson(paginatedListUsersMockResponse)));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/roles/%s".formatted(MOCK_ROLE_UUID)))
                        .willReturn(WireMock.okJson(roleDetailMockResponse)));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/roles/%s/users".formatted(MOCK_ROLE_UUID)))
                        .willReturn(WireMock.okJson(listUsersMockResponse)));
    }
}
