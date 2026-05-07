package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.auth.RoleRequestDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.*;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.AuthenticationCache;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.RoleManagementService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service(Resource.Codes.ROLE)
@Transactional
public class RoleManagementServiceImpl implements RoleManagementService {

    private RoleManagementApiClient roleManagementApiClient;
    private AttributeEngine attributeEngine;
    private AuthenticationCache authenticationCache;

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAuthenticationCache(AuthenticationCache authenticationCache) {
        this.authenticationCache = authenticationCache;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.LIST)
    public List<RoleDto> listRoles() {
        return roleManagementApiClient.getRoles().getData();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public RoleDetailDto getRole(String roleUuid) {
        RoleDetailDto dto = roleManagementApiClient.getRoleDetail(roleUuid);
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.ROLE, UUID.fromString(roleUuid)));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.CREATE)
    public RoleDetailDto createRole(RoleRequestDto request) throws NotFoundException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.ROLE, request.getCustomAttributes());
        com.czertainly.api.model.core.auth.RoleRequestDto requestDto = new com.czertainly.api.model.core.auth.RoleRequestDto();
        requestDto.setName(request.getName());
        requestDto.setDescription(request.getDescription());
        requestDto.setEmail(request.getEmail());
        requestDto.setSystemRole(false);
        RoleDetailDto dto = roleManagementApiClient.createRole(requestDto);
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ROLE, UUID.fromString(dto.getUuid()), request.getCustomAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public RoleDetailDto updateRole(String roleUuid, RoleRequestDto request) throws NotFoundException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.ROLE, request.getCustomAttributes());
        com.czertainly.api.model.core.auth.RoleRequestDto requestDto = new com.czertainly.api.model.core.auth.RoleRequestDto();
        requestDto.setName(request.getName());
        requestDto.setDescription(request.getDescription());
        requestDto.setEmail(request.getEmail());
        requestDto.setSystemRole(false);
        RoleDetailDto dto = roleManagementApiClient.updateRole(roleUuid, requestDto);
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ROLE, UUID.fromString(dto.getUuid()), request.getCustomAttributes()));
        authenticationCache.evictAll();
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DELETE)
    public void deleteRole(String roleUuid) {
        roleManagementApiClient.deleteRole(roleUuid);
        attributeEngine.deleteObjectAttributeContent(Resource.ROLE, UUID.fromString(roleUuid));
        authenticationCache.evictAll();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public SubjectPermissionsDto getRolePermissions(String roleUuid) {
        return roleManagementApiClient.getPermissions(roleUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public SubjectPermissionsDto addPermissions(String roleUuid, RolePermissionsRequestDto request) {
        checkSystemRole(roleUuid);
        SubjectPermissionsDto result = roleManagementApiClient.savePermissions(roleUuid, request);
        authenticationCache.evictAll();
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public ResourcePermissionsDto getRoleResourcePermission(String roleUuid, String resourceUuid) {
        return roleManagementApiClient.getPermissionResource(roleUuid, resourceUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public List<ObjectPermissionsDto> getResourcePermissionObjects(String roleUuid, String resourceUuid) {
        return roleManagementApiClient.getResourcePermissionObjects(roleUuid, resourceUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public void addResourcePermissionObjects(String roleUuid, String resourceUuid, List<ObjectPermissionsRequestDto> request) {
        checkSystemRole(roleUuid);
        roleManagementApiClient.addResourcePermissionObjects(roleUuid, resourceUuid, request);
        authenticationCache.evictAll();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public void updateResourcePermissionObjects(String roleUuid, String resourceUuid, String objectUuid, ObjectPermissionsRequestDto request) {
        checkSystemRole(roleUuid);
        roleManagementApiClient.updateResourcePermissionObjects(roleUuid, resourceUuid, objectUuid, request);
        authenticationCache.evictAll();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public void removeResourcePermissionObjects(String roleUuid, String resourceUuid, String objectUuid) {
        checkSystemRole(roleUuid);
        roleManagementApiClient.removeResourcePermissionObjects(roleUuid, resourceUuid, objectUuid);
        authenticationCache.evictAll();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public List<UserDto> getRoleUsers(String roleUuid) {
        return roleManagementApiClient.getRoleUsers(roleUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public RoleDetailDto updateUsers(String roleUuid, List<String> userUuids) {
        RoleDetailDto result = roleManagementApiClient.updateUsers(roleUuid, userUuids);
        authenticationCache.evictAll();
        return result;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        RoleDetailDto roleDetailDto = roleManagementApiClient.getRoleDetail(objectUuid.toString());
        return new NameAndUuidDto(roleDetailDto.getUuid(), roleDetailDto.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }


    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        throw new NotSupportedException("Listing of resource objects is not supported for resource roles.");
    }

    @Override
    @ExternalAuthorization(resource = Resource.ROLE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getRole(uuid.toString());
    }

    private void checkSystemRole(String roleUuid) {
        RoleDetailDto roleDetailDto = roleManagementApiClient.getRoleDetail(roleUuid);
        if (Boolean.TRUE.equals(roleDetailDto.getSystemRole())) {
            throw new ValidationException("Cannot edit permissions of system role: " + roleDetailDto.getName());
        }
    }
}
