package com.czertainly.core.service;

import com.czertainly.api.model.client.auth.UpdateUserRequestDto;
import com.czertainly.api.model.core.auth.UserDetailDto;
import com.czertainly.core.security.authn.client.AuthenticationCache;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.SessionTableHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

class UserManagementServiceCacheEvictionTest extends BaseSpringBootTest {

    @Autowired
    private UserManagementService userManagementService;

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

    @Test
    void updateUser_evictsUserCache() throws Exception {
        // given
        UUID userUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.updateUser(Mockito.eq(userUuid.toString()), Mockito.any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCustomAttributes(List.of());

        // when
        userManagementService.updateUser(userUuid.toString(), request);

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateUserInternal_evictsUserCache() throws Exception {
        // given
        UUID userUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.updateUser(Mockito.eq(userUuid.toString()), Mockito.any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.updateUserInternal(userUuid.toString(), new UpdateUserRequestDto(), "", "");

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void deleteUser_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();

        // when
        userManagementService.deleteUser(userUuid.toString());

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void disableUser_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.disableUser(userUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.disableUser(userUuid.toString());

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateRoles_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.updateRoles(Mockito.eq(userUuid.toString()), Mockito.any()))
                .thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.updateRoles(userUuid.toString(), List.of());

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void updateRole_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        UUID roleUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.updateRole(userUuid.toString(), roleUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.updateRole(userUuid.toString(), roleUuid.toString());

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    @Test
    void removeRole_evictsUserCache() {
        // given
        UUID userUuid = UUID.randomUUID();
        UUID roleUuid = UUID.randomUUID();
        Mockito.when(userManagementApiClient.removeRole(userUuid.toString(), roleUuid.toString())).thenReturn(userDetailDto(userUuid.toString()));

        // when
        userManagementService.removeRole(userUuid.toString(), roleUuid.toString());

        // then
        Mockito.verify(authenticationCache).evictByUserUuid(userUuid);
    }

    private static UserDetailDto userDetailDto(String uuid) {
        UserDetailDto dto = new UserDetailDto();
        dto.setUuid(uuid);
        dto.setUsername("user-" + uuid);
        return dto;
    }
}
