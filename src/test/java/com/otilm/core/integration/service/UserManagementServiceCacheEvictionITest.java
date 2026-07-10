package com.otilm.core.integration.service;

import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.UserManagementExternalService;
import com.otilm.core.service.UserManagementInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SessionTableHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserManagementServiceCacheEvictionITest extends BaseSpringBootTest {

    @Autowired
    private UserManagementExternalService userManagementService;

    @Autowired
    private UserManagementInternalService userManagementInternalService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private UserManagementApiClient userManagementApiClient;

    @MockitoBean
    private AuthenticationCache authenticationCache;

    @BeforeEach
    void setupSessionTables() {
        SessionTableHelper.createSessionTables(jdbcTemplate);
    }

    @AfterEach
    void tearDownSessionTables() {
        SessionTableHelper.dropSessionTables(jdbcTemplate);
    }

    @Test
    void updateUser_evictsUserCache() throws Exception {
        // given
        UUID userUuid = UUID.randomUUID();
        when(userManagementApiClient.updateUser(eq(userUuid.toString()), any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCustomAttributes(List.of());

        // when
        userManagementService.updateUser(userUuid.toString(), request);

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateUserInternal_evictsUserCache() throws Exception {
        // given
        UUID userUuid = UUID.randomUUID();
        when(userManagementApiClient.updateUser(eq(userUuid.toString()), any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementInternalService.updateUserInternal(userUuid.toString(), new UpdateUserRequestDto(), "", "");

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void deleteUser_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();

        // when
        userManagementService.deleteUser(userUuid.toString());

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void disableUser_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        when(userManagementApiClient.disableUser(userUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.disableUser(userUuid.toString());

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateRoles_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        when(userManagementApiClient.updateRoles(eq(userUuid.toString()), any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.updateRoles(userUuid.toString(), List.of());

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateRole_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        UUID roleUuid = UUID.randomUUID();
        when(userManagementApiClient.updateRole(userUuid.toString(), roleUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.updateRole(userUuid.toString(), roleUuid.toString());

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void removeRole_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        UUID roleUuid = UUID.randomUUID();
        when(userManagementApiClient.removeRole(userUuid.toString(), roleUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.removeRole(userUuid.toString(), roleUuid.toString());

        // then
        verify(authenticationCache).evictByUserUuid(userUuid);
    }

    private static UserDetailDto userDetailDto(String uuid) {
        UserDetailDto dto = new UserDetailDto();
        dto.setUuid(uuid);
        dto.setUsername("user-" + uuid);
        return dto;
    }
}
