package com.czertainly.core.util;

import com.czertainly.api.model.core.auth.*;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.auth.ResourceSyncRequestDto;
import com.czertainly.core.security.authn.client.ResourceApiClient;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

public class DatabaseAuthMigration {

    private static final String AUTH_SERVICE_BASE_URL_PROPERTY = "AUTH_SERVICE_BASE_URL";

    private static String authUrl;
    private static WebClient client;

    private static ResourceApiClient resourceApiClient;
    private static RoleManagementApiClient roleManagementApiClient;
    private static UserManagementApiClient userManagementApiClient;

    private DatabaseAuthMigration() {

    }

    public static String getAuthServiceUrl() throws IOException, URISyntaxException {
        if (authUrl != null && !authUrl.isEmpty()) {
            return authUrl;
        }

        String authServiceUrl = System.getenv(AUTH_SERVICE_BASE_URL_PROPERTY);
        if (authServiceUrl != null && !authServiceUrl.isEmpty()) {
            return authServiceUrl;
        }

        ClassLoader classLoader = DatabaseAuthMigration.class.getClassLoader();
        URL resource = classLoader.getResource("application.properties");
        if (resource == null) {
            return null;
        }

        File file = new File(resource.toURI());
        final Properties properties = new Properties();
        try (InputStream targetStream = new FileInputStream(file)) {
            properties.load(targetStream);
        }
        String[] splitData = ((String) properties.get("auth-service.base-url")).split(AUTH_SERVICE_BASE_URL_PROPERTY);
        return splitData[splitData.length - 1].replace("}", "");
    }

    public static void seedResources(Map<Resource, List<ResourceAction>> resources) throws IOException, URISyntaxException {
        List<ResourceSyncRequestDto> resourceDtos = new ArrayList<>();

        for (Map.Entry<Resource, List<ResourceAction>> resourceEntry : resources.entrySet()) {
            ResourceSyncRequestDto requestDto = new ResourceSyncRequestDto();
            requestDto.setName(com.czertainly.core.model.auth.Resource.findByCode(resourceEntry.getKey().getCode()));
            requestDto.setActions(resourceEntry.getValue().stream().map(ResourceAction::getCode).toList());

            resourceDtos.add(requestDto);
        }

        getResourceApiClient().addResources(resourceDtos);
    }

    public static Map<String, String> getSystemRolesMapping() throws IOException, URISyntaxException {
        HashMap<String, String> systemRolesMapping = new HashMap<>();
        List<RoleDto> roles = getRoleManagementApiClient().getRoles().getData();
        for (RoleDto role : roles) {
            if (Boolean.TRUE.equals(role.getSystemRole())) {
                systemRolesMapping.put(role.getName(), role.getUuid());
            }
        }

        return systemRolesMapping;
    }

    public static UserDetailDto createUser(UserRequestDto request, List<String> roleUuids) throws IOException, URISyntaxException {
        UserDetailDto user = getOrCreateUser(getUserManagementApiClient(), request);
        return getUserManagementApiClient().updateRoles(user.getUuid(), roleUuids);
    }

    public static RoleDetailDto createRole(RoleRequestDto request, Map<Resource, List<ResourceAction>> resourcesActions) throws IOException, URISyntaxException {
        RolePermissionsRequestDto permissionsRequest = new RolePermissionsRequestDto();
        permissionsRequest.setAllowAllResources(resourcesActions.isEmpty());
        permissionsRequest.setResources(new ArrayList<>());
        for (Map.Entry<Resource, List<ResourceAction>> resourceEntry : resourcesActions.entrySet()) {
            List<ResourceAction> resourceActions = resourceEntry.getValue();
            ResourcePermissionsRequestDto resourcePermissionsRequest = new ResourcePermissionsRequestDto();
            resourcePermissionsRequest.setName(resourceEntry.getKey().getCode());
            resourcePermissionsRequest.setAllowAllActions(resourceActions == null || resourceActions.isEmpty());
            resourcePermissionsRequest.setActions(resourceActions == null ? null : resourceActions.stream().map(ResourceAction::getCode).toList());
            resourcePermissionsRequest.setObjects(List.of());

            permissionsRequest.getResources().add(resourcePermissionsRequest);
        }

        request.setPermissions(permissionsRequest);
        return getOrCreateRole(getRoleManagementApiClient(), request);
    }

    /**
     * Idempotently creates a role: if a role with the requested name already exists — e.g. a prior,
     * interrupted migration run already created it in the Auth Service — the existing role is returned
     * instead of failing with ENTITY_NOT_UNIQUE. Schema migrations that call the Auth Service must be
     * safe to re-run (Flyway can re-execute a migration that was interrupted after the cross-service
     * POST but before its history row was committed).
     */
    public static RoleDetailDto getOrCreateRole(RoleManagementApiClient roleClient, RoleRequestDto request) {
        for (RoleDto existing : roleClient.getRoles().getData()) {
            if (existing.getName().equals(request.getName())) {
                return roleClient.getRoleDetail(existing.getUuid());
            }
        }
        return roleClient.createRole(request);
    }

    /**
     * Idempotently creates a user: if a user with the requested username already exists, the existing
     * user is returned instead of failing with ENTITY_NOT_UNIQUE. See {@link #getOrCreateRole}.
     */
    public static UserDetailDto getOrCreateUser(UserManagementApiClient userClient, UserRequestDto request) {
        for (UserDto existing : userClient.getUsers().getData()) {
            if (existing.getUsername().equals(request.getUsername())) {
                return userClient.getUserDetail(existing.getUuid());
            }
        }
        return userClient.createUser(request);
    }

    public static void updateRolePermissions(String roleUuid, Map<Resource, List<ResourceAction>> resourcesActions) throws IOException, URISyntaxException {
        Map<Resource, List<ResourceAction>> resourcesActionsCopy = new EnumMap<>(resourcesActions);
        SubjectPermissionsDto permissions = getRoleManagementApiClient().getPermissions(roleUuid);

        List<ResourcePermissionsRequestDto> resourcePermissionsRequests = new ArrayList<>();
        for (ResourcePermissionsDto resourcePermissions : permissions.getResources()) {
            ResourcePermissionsRequestDto requestDto = new ResourcePermissionsRequestDto();
            requestDto.setName(resourcePermissions.getName());
            requestDto.setAllowAllActions(resourcePermissions.getAllowAllActions());

            // update actions
            List<ResourceAction> resourceActions;
            Resource resource = Resource.findByCode(resourcePermissions.getName());
            if ((resourceActions = resourcesActionsCopy.get(resource)) == null) {
                requestDto.setActions(resourcePermissions.getActions());
            } else {
                // merge actions for resource
                HashSet<String> mergedActions = new HashSet<>(resourcePermissions.getActions());
                for (ResourceAction action : resourceActions) {
                    mergedActions.add(action.getCode());
                }
                requestDto.setActions(mergedActions.stream().toList());
            }

            // copy objects permissions
            ArrayList<ObjectPermissionsRequestDto> objectsPermissions = new ArrayList<>();
            for (ObjectPermissionsDto objectPermissions : resourcePermissions.getObjects()) {
                ObjectPermissionsRequestDto objectPermissionDto = new ObjectPermissionsRequestDto();
                objectPermissionDto.setUuid(objectPermissions.getUuid());
                objectPermissionDto.setName(objectPermissions.getName());
                objectPermissionDto.setAllow(objectPermissions.getAllow());
                objectPermissionDto.setDeny(objectPermissions.getDeny());
                objectsPermissions.add(objectPermissionDto);
            }
            requestDto.setObjects(objectsPermissions);
            resourcePermissionsRequests.add(requestDto);

            resourcesActionsCopy.remove(resource);
        }

        if (!resourcesActionsCopy.isEmpty()) {
            for (Map.Entry<Resource, List<ResourceAction>> resourceEntry : resourcesActionsCopy.entrySet()) {
                Resource resource = resourceEntry.getKey();
                List<ResourceAction> resourceActions = resourceEntry.getValue();

                ResourcePermissionsRequestDto requestDto = new ResourcePermissionsRequestDto();
                requestDto.setName(resource.getCode());
                requestDto.setAllowAllActions(resourceActions == null || resourceActions.isEmpty());
                requestDto.setActions(resourceActions == null ? List.of() : resourceActions.stream().map(ResourceAction::getCode).toList());
                requestDto.setObjects(List.of());
                resourcePermissionsRequests.add(requestDto);
            }
        }

        RolePermissionsRequestDto request = new RolePermissionsRequestDto();
        request.setAllowAllResources(permissions.getAllowAllResources());
        request.setResources(resourcePermissionsRequests);

        getRoleManagementApiClient().savePermissions(roleUuid, request);
    }

    public static RoleManagementApiClient getRoleManagementApiClient() throws IOException, URISyntaxException {
        if (roleManagementApiClient == null) {
            roleManagementApiClient = new RoleManagementApiClient(getAuthServiceUrl(), client);
        }

        return roleManagementApiClient;
    }

    public static UserManagementApiClient getUserManagementApiClient() throws IOException, URISyntaxException {
        if (userManagementApiClient == null) {
            userManagementApiClient = new UserManagementApiClient(getAuthServiceUrl(), client);
        }

        return userManagementApiClient;
    }

    public static ResourceApiClient getResourceApiClient() throws IOException, URISyntaxException {
        if (resourceApiClient == null) {
            resourceApiClient = new ResourceApiClient(getAuthServiceUrl(), client);
        }

        return resourceApiClient;
    }
}
