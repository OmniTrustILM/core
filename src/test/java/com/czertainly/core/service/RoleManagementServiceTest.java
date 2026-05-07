package com.czertainly.core.service;

import com.czertainly.api.model.client.auth.RoleRequestDto;
import com.czertainly.api.model.core.auth.*;
import com.czertainly.core.security.authn.client.AuthenticationCache;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

class RoleManagementServiceTest extends BaseSpringBootTest {

    @Autowired
    private RoleManagementService roleManagementService;

    @MockitoBean
    private RoleManagementApiClient roleManagementApiClient;

    @MockitoBean
    private AuthenticationCache authenticationCache;

    @Test
    void updateRole_evictsEntireCache() throws Exception {
        // given
        String roleUuid = UUID.randomUUID().toString();
        RoleDetailDto roleDetailDto = roleDetailDto(roleUuid, false);
        Mockito.when(roleManagementApiClient.updateRole(Mockito.eq(roleUuid), Mockito.any())).thenReturn(roleDetailDto);

        RoleRequestDto request = new RoleRequestDto();
        request.setName("test-role");
        request.setCustomAttributes(List.of());

        // when
        roleManagementService.updateRole(roleUuid, request);

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void deleteRole_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();

        // when
        roleManagementService.deleteRole(roleUuid);

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void addPermissions_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();
        Mockito.when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(roleDetailDto(roleUuid, false));
        Mockito.when(roleManagementApiClient.savePermissions(Mockito.eq(roleUuid), Mockito.any()))
                .thenReturn(new SubjectPermissionsDto());

        // when
        roleManagementService.addPermissions(roleUuid, new RolePermissionsRequestDto());

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void addResourcePermissionObjects_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();
        String resourceUuid = UUID.randomUUID().toString();
        Mockito.when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(roleDetailDto(roleUuid, false));

        // when
        roleManagementService.addResourcePermissionObjects(roleUuid, resourceUuid, List.of());

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void updateResourcePermissionObjects_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();
        String resourceUuid = UUID.randomUUID().toString();
        String objectUuid = UUID.randomUUID().toString();
        Mockito.when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(roleDetailDto(roleUuid, false));

        // when
        roleManagementService.updateResourcePermissionObjects(roleUuid, resourceUuid, objectUuid, new ObjectPermissionsRequestDto());

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void removeResourcePermissionObjects_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();
        String resourceUuid = UUID.randomUUID().toString();
        String objectUuid = UUID.randomUUID().toString();
        Mockito.when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(roleDetailDto(roleUuid, false));

        // when
        roleManagementService.removeResourcePermissionObjects(roleUuid, resourceUuid, objectUuid);

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    @Test
    void updateUsers_evictsEntireCache() {
        // given
        String roleUuid = UUID.randomUUID().toString();
        Mockito.when(roleManagementApiClient.updateUsers(Mockito.eq(roleUuid), Mockito.any()))
                .thenReturn(roleDetailDto(roleUuid, false));

        // when
        roleManagementService.updateUsers(roleUuid, List.of());

        // then
        Mockito.verify(authenticationCache).evictAll();
    }

    private static RoleDetailDto roleDetailDto(String uuid, boolean systemRole) {
        RoleDetailDto dto = new RoleDetailDto();
        dto.setUuid(uuid);
        dto.setName("role-" + uuid);
        dto.setSystemRole(systemRole);
        return dto;
    }
}
