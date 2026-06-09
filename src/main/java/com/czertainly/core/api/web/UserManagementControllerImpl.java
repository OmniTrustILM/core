package com.czertainly.core.api.web;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.UserManagementController;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.client.auth.UserIdentificationRequestDto;
import com.otilm.api.model.core.auth.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.UserManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.security.cert.CertificateException;
import java.util.List;

@RestController
public class UserManagementControllerImpl implements UserManagementController {

    private UserManagementService userManagementService;

    @Autowired
    public void setUserManagementService(UserManagementService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.LIST)
    public List<UserDto> listUsers() {
        return userManagementService.listUsers();
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.DETAIL)
    public UserDetailDto getUser(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        return userManagementService.getUser(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.CREATE)
    public ResponseEntity<UserDetailDto> createUser(AddUserRequestDto request) throws NotFoundException, CertificateException, AttributeException {
        UserDetailDto userDto = userManagementService.createUser(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(userDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(userDto);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.UPDATE)
    public UserDetailDto updateUser(@LogResource(uuid = true) String userUuid, UpdateUserRequestDto request) throws NotFoundException, CertificateException, AttributeException {
        return userManagementService.updateUser(userUuid, request);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.ENABLE)
    public UserDetailDto enableUser(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        return userManagementService.enableUser(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.DISABLE)
    public UserDetailDto disableUser(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        return userManagementService.disableUser(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.DELETE)
    public void deleteUser(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        userManagementService.deleteUser(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, affiliatedResource = Resource.ROLE, operation = Operation.LIST)
    public List<RoleDto> getUserRoles(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        return userManagementService.getUserRoles(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, affiliatedResource = Resource.ROLE, operation = Operation.UPDATE)
    public UserDetailDto updateRoles(@LogResource(uuid = true) String userUuid, @LogResource(uuid = true, affiliated = true) List<String> roleUuids) throws NotFoundException {
        return userManagementService.updateRoles(userUuid, roleUuids);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, affiliatedResource = Resource.ROLE, operation = Operation.ADD)
    public UserDetailDto addRole(@LogResource(uuid = true) String userUuid, @LogResource(uuid = true, affiliated = true) String roleUuid) throws NotFoundException {
        return userManagementService.updateRole(userUuid, roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, affiliatedResource = Resource.ROLE, operation = Operation.REMOVE)
    public UserDetailDto removeRole(@LogResource(uuid = true) String userUuid, @LogResource(uuid = true, affiliated = true) String roleUuid) throws NotFoundException {
        return userManagementService.removeRole(userUuid, roleUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.GET_PERMISSIONS)
    public SubjectPermissionsDto getPermissions(@LogResource(uuid = true) String userUuid) throws NotFoundException {
        return userManagementService.getPermissions(userUuid);
    }

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.IDENTIFY)
    public UserDetailDto identifyUser(UserIdentificationRequestDto request) throws NotFoundException, CertificateException {
        return userManagementService.identifyUser(request);
    }
}
