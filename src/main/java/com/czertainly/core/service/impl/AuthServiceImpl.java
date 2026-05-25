package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.auth.UpdateUserRequestDto;
import com.czertainly.api.model.core.auth.*;
import com.czertainly.core.auth.ContextRefreshListener;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.ResourceApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.AnyPrincipalEndpoint;
import com.czertainly.core.security.authz.SelfPrincipalEndpoint;
import com.czertainly.core.service.AuthExternalService;
import com.czertainly.core.service.UserManagementService;
import com.czertainly.core.util.AuthHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Transactional
public class AuthServiceImpl implements AuthExternalService {

    private UserManagementApiClient userManagementApiClient;
    private ResourceApiClient resourceApiClient;
    private UserManagementService userManagementService;

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
    public void setUserManagementService(UserManagementService userManagementService) {
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
        return new UserProfileDetailDto(userDetailDto, new UserProfilePermissionsDto(getAllowedResourceListings(userProfileDto)));
    }

    @Override
    @AnyPrincipalEndpoint
    public List<AuthResourceDto> getAuthResources() {
        return resourceApiClient.getAuthResources();
    }

    @Override
    @SelfPrincipalEndpoint
    public UserDetailDto updateUserProfile(UpdateUserRequestDto request) throws NotFoundException, CertificateException {
        UserProfileDto userProfileDto = AuthHelper.getUserProfile();
        UserDetailDto detail = userManagementApiClient.getUserDetail(userProfileDto.getUser().getUuid());
        String certificateUuid = "";
        String certificateFingerprint = "";
        if (detail.getCertificate() != null) {
            if (detail.getCertificate().getUuid() != null) certificateUuid = detail.getCertificate().getUuid();
            if (detail.getCertificate().getFingerprint() != null)
                certificateFingerprint = detail.getCertificate().getFingerprint();
        }
        return userManagementService.updateUserInternal(userProfileDto.getUser().getUuid(), request, certificateUuid, certificateFingerprint);
    }

    private List<Resource> getAllowedResourceListings(UserProfileDto userProfileDto) {
        List<Resource> allowedListings;
        List<Resource> allListings = contextRefreshListener.getResources().stream()
                .filter(syncResource -> syncResource.getActions().contains(ResourceAction.LIST.getCode()))
                .map(syncResource -> Resource.findByCode(syncResource.getName().getCode())).sorted(Comparator.comparing(Resource::getCode)).toList();

        if (Boolean.TRUE.equals(userProfileDto.getPermissions().getAllowAllResources())) {
            return allListings;
        }

        Map<Resource, ResourcePermissionsDto> mappedUserPermissions = userProfileDto.getPermissions().getResources().stream().collect(Collectors.toMap(resource -> Resource.findByCode(resource.getName()), resource -> resource));
        ResourcePermissionsDto groupPermissions = mappedUserPermissions.get(Resource.GROUP);
        boolean hasGroupMembersPermissions = groupPermissions != null
                && (groupPermissions.getAllowAllActions()
                || groupPermissions.getObjects().stream().anyMatch(obj -> obj.getAllow().contains(ResourceAction.MEMBERS.getCode())));

        allowedListings = new ArrayList<>();
        for (Resource resource : allListings) {
            ResourcePermissionsDto resourcePermissions = mappedUserPermissions.get(resource);

            if (resource.hasOwner() || (resource.hasGroups() && hasGroupMembersPermissions)) {
                allowedListings.add(resource);
                continue;
            }
            if (resourcePermissions != null &&
                    (resourcePermissions.getAllowAllActions()
                            || resourcePermissions.getActions().contains(ResourceAction.LIST.getCode())
                            || resourcePermissions.getObjects().stream().anyMatch(obj -> obj.getAllow().contains(ResourceAction.LIST.getCode())))
            ) {
                allowedListings.add(resource);
            }
        }
        return allowedListings;
    }

}
