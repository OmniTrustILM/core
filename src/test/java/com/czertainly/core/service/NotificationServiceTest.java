package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.notification.NotificationRequestDto;
import com.czertainly.api.model.client.notification.NotificationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.repository.notifications.NotificationRecipientRepository;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@SpringBootTest
@Transactional
@Rollback
class NotificationServiceTest extends BaseSpringBootTest {

    private static final int AUTH_SERVICE_MOCK_PORT = 10001;
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

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:" + AUTH_SERVICE_MOCK_PORT);
    }

    @BeforeEach
    public void setUp() {
        var authInfo = AuthHelper.getUserIdentification();
        mockUser1Uuid = authInfo.getUuid();
    }

    @Test
    void testNotificationsOperations() throws NotFoundException {
        setupAuthServiceMock();

        notificationInternalService.createNotificationForRole("TestMessage", null, MOCK_ROLE_UUID, Resource.DISCOVERY, UUID.randomUUID().toString());
        notificationInternalService.createNotificationForGroup("TestMessage2", null, MOCK_GROUP_1_UUID, Resource.DISCOVERY, "%s,%s".formatted(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        notificationInternalService.createNotificationForUser("TestMessage3", null, mockUser1Uuid, Resource.DISCOVERY, UUID.randomUUID().toString());

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

        notificationExternalService.bulkDeleteNotifications(notificationRecipientRepository.findAll().stream().map(n -> n.getNotificationUuid().toString()).toList());

        // all notifications that are present in DB are send to bulk delete, but deleted should be only those of logged user
        Assertions.assertEquals(3, notificationRecipientRepository.findAll().size());

        mockServer.stop();
    }

    private void setupAuthServiceMock() {
        mockServer = new WireMockServer(AUTH_SERVICE_MOCK_PORT);
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
                """.formatted(mockUser1Uuid, MOCK_GROUP_1_UUID, MOCK_GROUP_2_UUID, MOCK_USER_2_UUID, MOCK_GROUP_1_UUID, MOCK_USER_3_UUID, MOCK_GROUP_2_UUID);

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

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users")).willReturn(WireMock.okJson(paginatedListUsersMockResponse)));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/%s".formatted(MOCK_ROLE_UUID))).willReturn(WireMock.okJson(roleDetailMockResponse)));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/%s/users".formatted(MOCK_ROLE_UUID))).willReturn(WireMock.okJson(listUsersMockResponse)));
    }
}
