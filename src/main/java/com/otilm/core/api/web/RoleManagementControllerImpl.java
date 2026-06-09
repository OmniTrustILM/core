package com.otilm.core.api.web;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.RoleManagementController;
import com.otilm.api.model.client.auth.RoleRequestDto;
import com.otilm.api.model.core.auth.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.RoleManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class RoleManagementControllerImpl implements RoleManagementController {

    private RoleManagementService roleManagementService;

    @Autowired
    public void setRoleManagementService(RoleManagementService roleManagementService) {
        this.roleManagementService = roleManagementService;
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.LIST)
    public List<RoleDto> listRoles() {
        return roleManagementService.listRoles();
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.DETAIL)
    public RoleDetailDto getRole(@LogResource(uuid = true) String roleUuid) throws NotFoundException {
        return roleManagementService.getRole(roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.CREATE)
    public ResponseEntity<RoleDetailDto> createRole(com.otilm.api.model.client.auth.RoleRequestDto request) throws NotFoundException, AttributeException {
        RoleDetailDto dto = roleManagementService.createRole(request);
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(dto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.UPDATE)
    public RoleDetailDto updateRole(@LogResource(uuid = true) String roleUuid, RoleRequestDto request) throws NotFoundException, AttributeException {
        return roleManagementService.updateRole(roleUuid, request);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.DELETE)
    public void deleteRole(@LogResource(uuid = true) String roleUuid) throws NotFoundException {
        roleManagementService.deleteRole(roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, affiliatedResource = Resource.USER, operation = Operation.LIST)
    public List<UserDto> getRoleUsers(@LogResource(uuid = true) String roleUuid) throws NotFoundException {
        return roleManagementService.getRoleUsers(roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, affiliatedResource = Resource.USER, operation = Operation.UPDATE)
    public RoleDetailDto updateUsers(@LogResource(uuid = true) String roleUuid, @LogResource(uuid = true, affiliated = true) List<String> userUuids) throws NotFoundException {
        return roleManagementService.updateUsers(roleUuid, userUuids);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.GET_PERMISSIONS)
    public SubjectPermissionsDto getRolePermissions(@LogResource(uuid = true) String roleUuid) throws NotFoundException {
        return roleManagementService.getRolePermissions(roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.UPDATE_PERMISSIONS)
    public SubjectPermissionsDto savePermissions(@LogResource(uuid = true) String roleUuid, RolePermissionsRequestDto request) throws NotFoundException {
        return roleManagementService.addPermissions(roleUuid, request);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.GET_PERMISSIONS)
    public ResourcePermissionsDto getRoleResourcePermissions(@LogResource(uuid = true) String roleUuid, String resourceUuid) throws NotFoundException {
        return roleManagementService.getRoleResourcePermission(roleUuid, resourceUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.GET_OBJECT_PERMISSIONS)
    public List<ObjectPermissionsDto> getResourcePermissionObjects(@LogResource(uuid = true) String roleUuid, String resourceUuid) throws NotFoundException {
        return roleManagementService.getResourcePermissionObjects(roleUuid, resourceUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.UPDATE_OBJECT_PERMISSIONS)
    public void addResourcePermissionObjects(@LogResource(uuid = true) String roleUuid, String resourceUuid, List<ObjectPermissionsRequestDto> request) throws NotFoundException {
        roleManagementService.addResourcePermissionObjects(roleUuid, resourceUuid, request);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.UPDATE_OBJECT_PERMISSIONS)
    public void updateResourcePermissionObjects(@LogResource(uuid = true) String roleUuid, String resourceUuid, String objectUuid, ObjectPermissionsRequestDto request) throws NotFoundException {
        roleManagementService.updateResourcePermissionObjects(roleUuid, resourceUuid, objectUuid, request);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.ROLE, operation = Operation.UPDATE_OBJECT_PERMISSIONS)
    public void removeResourcePermissionObjects(@LogResource(uuid = true) String roleUuid, String resourceUuid, String objectUuid) throws NotFoundException {
        roleManagementService.removeResourcePermissionObjects(roleUuid, resourceUuid, objectUuid);
    }
}
