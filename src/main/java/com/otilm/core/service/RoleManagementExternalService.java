package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.RoleRequestDto;
import com.otilm.api.model.core.auth.*;

import java.util.List;

public interface RoleManagementExternalService {

    List<RoleDto> listRoles();

    RoleDetailDto getRole(String roleUuid);

    RoleDetailDto createRole(RoleRequestDto request) throws NotFoundException, AttributeException;

    RoleDetailDto updateRole(String roleUuid, RoleRequestDto request) throws NotFoundException, AttributeException;

    void deleteRole(String roleUuid);

    SubjectPermissionsDto getRolePermissions(String roleUuid);

    SubjectPermissionsDto addPermissions(String roleUuid, RolePermissionsRequestDto request);

    ResourcePermissionsDto getRoleResourcePermission(String roleUuid, String resourceUuid);

    List<ObjectPermissionsDto> getResourcePermissionObjects(String roleUuid, String resourceUuid);

    void addResourcePermissionObjects(String roleUuid, String resourceUuid, List<ObjectPermissionsRequestDto> request);

    void updateResourcePermissionObjects(String roleUuid, String resourceUuid, String objectUuid, ObjectPermissionsRequestDto request);

    void removeResourcePermissionObjects(String roleUuid, String resourceUuid, String objectUuid);

    List<UserDto> getRoleUsers(String roleUuid);

    RoleDetailDto updateUsers(String roleUuid, List<String> userUuids);
}
