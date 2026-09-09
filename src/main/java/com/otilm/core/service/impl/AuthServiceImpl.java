package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.core.auth.AuthResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.ResourceActionsDto;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserProfileDetailDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.auth.UserProfilePermissionsDto;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.security.authn.client.ResourceApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.SelfPrincipalEndpoint;
import com.otilm.core.service.AuthExternalService;
import com.otilm.core.service.UserManagementInternalService;
import com.otilm.core.util.AuthHelper;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthServiceImpl implements AuthExternalService {

    private static final List<Resource> DEFAULT_ALLOWED_LISTINGS = List.of(Resource.DASHBOARD, Resource.APPROVAL);

    private UserManagementApiClient userManagementApiClient;
    private ResourceApiClient resourceApiClient;
    private UserManagementInternalService userManagementService;

    private ContextRefreshListener contextRefreshListener;

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setResourceApiClient(ResourceApiClient resourceApiClient) {
        this.resourceApiClient = resourceApiClient;
    }

    @Autowired
    public void setUserManagementInternalService(UserManagementInternalService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @Autowired
    public void setResourceListener(ContextRefreshListener contextRefreshListener) {
        this.contextRefreshListener = contextRefreshListener;
    }

    @Override
    @SelfPrincipalEndpoint
    public UserProfileDetailDto getAuthProfile() {
        UserProfileDto userProfileDto = AuthHelper.getUserProfile();
        UserDetailDto userDetailDto = userManagementApiClient.getUserDetail(userProfileDto.getUser().getUuid());

        // load listing permissions
        return new UserProfileDetailDto(userDetailDto, new UserProfilePermissionsDto(
                getAllowedResourceListings(userProfileDto), getAllowedResourceActions(userProfileDto)));
    }

    @Override
    @AnyPrincipalEndpoint
    public List<AuthResourceDto> getAuthResources() {
        return resourceApiClient.getAuthResources();
    }

    @Override
    @SelfPrincipalEndpoint
    public UserDetailDto updateUserProfile(UpdateUserRequestDto request)
            throws NotFoundException, CertificateException {
        UserProfileDto userProfileDto = AuthHelper.getUserProfile();
        UserDetailDto detail = userManagementApiClient.getUserDetail(userProfileDto.getUser().getUuid());
        String certificateUuid = "";
        String certificateFingerprint = "";
        if (detail.getCertificate() != null) {
            if (detail.getCertificate().getUuid() != null) {
                certificateUuid = detail.getCertificate().getUuid();
            }
            if (detail.getCertificate().getFingerprint() != null) {
                certificateFingerprint = detail.getCertificate().getFingerprint();
            }
        }
        return userManagementService
                .updateUserInternal(userProfileDto.getUser().getUuid(), request, certificateUuid,
                        certificateFingerprint);
    }

    /** Shared by both permission-derived fields, so a change to how a grant is looked up reaches each of them. */
    private static Map<Resource, ResourcePermissionsDto> mapPermissionsByResource(UserProfileDto userProfileDto) {
        return userProfileDto
                .getPermissions()
                .getResources()
                .stream()
                .collect(Collectors.toMap(resource -> Resource.findByCode(resource.getName()), resource -> resource));
    }

    private List<Resource> getAllowedResourceListings(UserProfileDto userProfileDto) {
        List<Resource> allowedListings;
        List<Resource> allListings = contextRefreshListener
                .getResources()
                .stream()
                .filter(syncResource -> syncResource.getActions().contains(ResourceAction.LIST.getCode()))
                .map(syncResource -> Resource.findByCode(syncResource.getName().getCode()))
                .sorted(Comparator.comparing(Resource::getCode))
                .toList();

        if (Boolean.TRUE.equals(userProfileDto.getPermissions().getAllowAllResources())) {
            return withDefaultListings(allListings);
        }

        Map<Resource, ResourcePermissionsDto> mappedUserPermissions = mapPermissionsByResource(userProfileDto);
        ResourcePermissionsDto groupPermissions = mappedUserPermissions.get(Resource.GROUP);
        boolean hasGroupMembersPermissions = groupPermissions != null
                && (groupPermissions.getAllowAllActions() || groupPermissions
                        .getObjects()
                        .stream()
                        .anyMatch(obj -> obj.getAllow().contains(ResourceAction.MEMBERS.getCode())));

        allowedListings = new ArrayList<>();
        for (Resource resource : allListings) {
            ResourcePermissionsDto resourcePermissions = mappedUserPermissions.get(resource);

            if (resource.hasOwner() || (resource.hasGroups() && hasGroupMembersPermissions)) {
                allowedListings.add(resource);
                continue;
            }
            if (resourcePermissions != null && (resourcePermissions.getAllowAllActions()
                    || resourcePermissions.getActions().contains(ResourceAction.LIST.getCode())
                    || resourcePermissions
                            .getObjects()
                            .stream()
                            .anyMatch(obj -> obj.getAllow().contains(ResourceAction.LIST.getCode())))) {
                allowedListings.add(resource);
            }
        }
        return withDefaultListings(allowedListings);
    }

    /** See {@link UserProfilePermissionsDto#getAllowedActions()} for the contract this computes. */
    private List<ResourceActionsDto> getAllowedResourceActions(UserProfileDto userProfileDto) {
        boolean allowAllResources = Boolean.TRUE.equals(userProfileDto.getPermissions().getAllowAllResources());
        Map<Resource, ResourcePermissionsDto> mappedUserPermissions = allowAllResources
                ? Map.of()
                : mapPermissionsByResource(userProfileDto);

        List<ResourceActionsDto> allowedActions = new ArrayList<>();
        for (ResourceSyncRequestDto syncResource : contextRefreshListener.getResources()) {
            Resource resource = Resource.findByCode(syncResource.getName().getCode());
            ResourcePermissionsDto resourcePermissions = mappedUserPermissions.get(resource);
            // Filtered out of the catalogue rather than mapped out of the grant: the authorization service may hold an
            // action code this build no longer declares, and findByCode throws on one, which would fail the whole
            // profile request over a permission the caller does not even need.
            List<ResourceAction> actions = syncResource
                    .getActions()
                    .stream()
                    .filter(actionCode -> isActionGranted(actionCode, allowAllResources, resourcePermissions))
                    .map(ResourceAction::findByCode)
                    // ANY reaches the catalogue from the annotations but is skipped by the auth service at sync, so a
                    // grant on it cannot exist. NONE is not skipped and would be stored as a real action; it only
                    // stays out of the catalogue because every annotated endpoint passes an explicit action rather
                    // than leaving the NONE default in place.
                    .filter(action -> action.getAccessType() != ResourceAction.AccessType.NOT_GRANTABLE)
                    .sorted(Comparator.comparing(ResourceAction::getCode))
                    .toList();

            if (!actions.isEmpty()) {
                allowedActions.add(new ResourceActionsDto(resource, actions));
            }
        }
        return allowedActions.stream().sorted(Comparator.comparing(entry -> entry.getResource().getCode())).toList();
    }

    private static boolean isActionGranted(String actionCode, boolean allowAllResources,
            ResourcePermissionsDto resourcePermissions) {
        if (allowAllResources) {
            return true;
        }
        if (resourcePermissions == null) {
            return false;
        }
        if (Boolean.TRUE.equals(resourcePermissions.getAllowAllActions())) {
            return true;
        }
        return resourcePermissions.getActions() != null && resourcePermissions.getActions().contains(actionCode);
    }

    private List<Resource> withDefaultListings(List<Resource> listings) {
        // append the missing defaults, then keep deterministic by-code order
        return Stream
                .concat(listings.stream(),
                        DEFAULT_ALLOWED_LISTINGS.stream().filter(defaultListing -> !listings.contains(defaultListing)))
                .sorted(Comparator.comparing(Resource::getCode))
                .toList();
    }

}
