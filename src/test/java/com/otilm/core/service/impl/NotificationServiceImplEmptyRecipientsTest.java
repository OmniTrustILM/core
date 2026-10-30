package com.otilm.core.service.impl;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserWithPaginationDto;
import com.otilm.core.dao.entity.notifications.Notification;
import com.otilm.core.dao.repository.notifications.NotificationRecipientRepository;
import com.otilm.core.dao.repository.notifications.NotificationRepository;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A group or role that resolves to no users is ordinary configuration, so it is reported by returning null. The caller
 * counts what was created and reports an event that reached no one; see {@code NotificationInternalNotificationITest}
 * for that half of the contract.
 */
class NotificationServiceImplEmptyRecipientsTest {

    private final NotificationRepository notificationRepository = mock(NotificationRepository.class);
    private final UserManagementApiClient userManagementApiClient = mock(UserManagementApiClient.class);
    private final RoleManagementApiClient roleManagementApiClient = mock(RoleManagementApiClient.class);

    private NotificationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new NotificationServiceImpl();
        service.setNotificationRepository(notificationRepository);
        service.setNotificationRecipientRepository(mock(NotificationRecipientRepository.class));
        service.setUserManagementApiClient(userManagementApiClient);
        service.setRoleManagementApiClient(roleManagementApiClient);
    }

    @Test
    void groupWithNoMembersCreatesNoNotificationAndDoesNotThrow() {
        UserWithPaginationDto noUsers = new UserWithPaginationDto();
        noUsers.setData(List.of());
        when(userManagementApiClient.getUsers()).thenReturn(noUsers);

        assertNull(service
                .createNotificationForGroup("Certificate status changed", null, UUID.randomUUID().toString(),
                        Resource.CERTIFICATE, UUID.randomUUID().toString()));

        verify(notificationRepository, never()).save(any());
    }

    @Test
    void roleWithNoMembersCreatesNoNotificationAndDoesNotThrow() {
        when(roleManagementApiClient.getRoleUsers(any())).thenReturn(List.of());

        assertNull(service
                .createNotificationForRole("Certificate status changed", null, UUID.randomUUID().toString(),
                        Resource.CERTIFICATE, UUID.randomUUID().toString()));

        verify(notificationRepository, never()).save(any());
    }

    @Test
    void groupWithMembersStillCreatesTheNotification() {
        UserDto member = new UserDto();
        member.setUuid(UUID.randomUUID().toString());
        UserWithPaginationDto users = new UserWithPaginationDto();
        users.setData(List.of(member));
        when(userManagementApiClient.getUsers()).thenReturn(users);

        assertNotNull(service
                .createNotificationForUsers("Certificate status changed", null, List.of(member.getUuid()),
                        Resource.CERTIFICATE, UUID.randomUUID().toString()));

        verify(notificationRepository).save(any(Notification.class));
    }
}
