package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.core.auth.AuthResourceDto;
import com.otilm.api.model.core.auth.ObjectActionsDto;
import com.otilm.api.model.core.auth.ObjectPermissionsDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.ResourceActionsDto;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserProfileDetailDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.auth.UserProfilePermissionsDto;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
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
import java.util.Set;
import java.util.UUID;
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
    private OwnerAssociationRepository ownerAssociationRepository;

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
    public void setOwnerAssociationRepository(OwnerAssociationRepository ownerAssociationRepository) {
        this.ownerAssociationRepository = ownerAssociationRepository;
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
        return new UserProfileDetailDto(userDetailDto,
                new UserProfilePermissionsDto(getAllowedResourceListings(userProfileDto),
                        getAllowedResourceActions(userProfileDto), getObjectActions(userProfileDto)));
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
        GroupMembership groupMembership = GroupMembership.of(mappedUserPermissions.get(Resource.GROUP));

        allowedListings = new ArrayList<>();
        List<Resource> ownedResourcesToCheck = new ArrayList<>();
        for (Resource resource : allListings) {
            if (hasListGrant(mappedUserPermissions.get(resource))) {
                allowedListings.add(resource);
            } else if (resource.hasOwner()) {
                ownedResourcesToCheck.add(resource);
            } else if (resource.hasGroups() && groupMembership.any()) {
                allowedListings.add(resource);
            }
        }
        allowedListings
                .addAll(findResourcesWithOwnedOrGroupAssignedObjects(ownedResourcesToCheck,
                        UUID.fromString(userProfileDto.getUser().getUuid()), groupMembership));
        return withDefaultListings(allowedListings);
    }

    private static boolean hasListGrant(ResourcePermissionsDto resourcePermissions) {
        return resourcePermissions != null && (Boolean.TRUE.equals(resourcePermissions.getAllowAllActions())
                || resourcePermissions.getActions() != null
                        && resourcePermissions.getActions().contains(ResourceAction.LIST.getCode())
                || objectsOf(resourcePermissions)
                        .anyMatch(obj -> obj.getAllow().contains(ResourceAction.LIST.getCode())));
    }

    private List<Resource> findResourcesWithOwnedOrGroupAssignedObjects(List<Resource> resources, UUID userUuid,
            GroupMembership groupMembership) {
        if (resources.isEmpty()) {
            return List.of();
        }
        String resourceNames = resources.stream().map(Resource::name).collect(Collectors.joining(",", "{", "}"));
        String groupUuids = groupMembership
                .groupUuids()
                .stream()
                .map(UUID::toString)
                .collect(Collectors.joining(",", "{", "}"));
        return ownerAssociationRepository
                .findResourcesWithOwnedOrGroupAssignedObjects(resourceNames, userUuid, groupMembership.allGroups(),
                        groupUuids)
                .stream()
                .map(Resource::valueOf)
                .toList();
    }

    /**
     * The groups whose members' access the user holds: an object assigned to one of them is listable and viewable by
     * the user, which is how group ownership reaches authorization.
     */
    private record GroupMembership(boolean allGroups, Set<UUID> groupUuids) {

        static GroupMembership of(ResourcePermissionsDto groupPermissions) {
            if (groupPermissions == null) {
                return new GroupMembership(false, Set.of());
            }
            boolean allGroups = Boolean.TRUE.equals(groupPermissions.getAllowAllActions())
                    || groupPermissions.getActions() != null
                            && groupPermissions.getActions().contains(ResourceAction.MEMBERS.getCode());
            Set<UUID> groupUuids = objectsOf(groupPermissions)
                    .filter(obj -> obj.getAllow().contains(ResourceAction.MEMBERS.getCode()))
                    .flatMap(obj -> parseUuid(obj.getUuid()))
                    .collect(Collectors.toSet());
            return new GroupMembership(allGroups, groupUuids);
        }

        boolean any() {
            return allGroups || !groupUuids.isEmpty();
        }

        // A malformed grant from the authorization service must not fail the whole profile request.
        private static Stream<UUID> parseUuid(String uuid) {
            try {
                return Stream.of(UUID.fromString(uuid));
            } catch (IllegalArgumentException e) {
                return Stream.empty();
            }
        }
    }

    private static Stream<ObjectPermissionsDto> objectsOf(ResourcePermissionsDto resourcePermissions) {
        return resourcePermissions.getObjects() == null ? Stream.empty() : resourcePermissions.getObjects().stream();
    }

    /** See {@link UserProfilePermissionsDto#getObjectActions()} for the contract this computes. */
    private List<ObjectActionsDto> getObjectActions(UserProfileDto userProfileDto) {
        if (Boolean.TRUE.equals(userProfileDto.getPermissions().getAllowAllResources())) {
            return List.of();
        }
        Map<Resource, List<String>> declaredActions = contextRefreshListener
                .getResources()
                .stream()
                .collect(Collectors
                        .toMap(syncResource -> Resource.findByCode(syncResource.getName().getCode()),
                                ResourceSyncRequestDto::getActions));

        List<ObjectActionsDto> objectActions = new ArrayList<>();
        mapPermissionsByResource(userProfileDto).forEach((resource, resourcePermissions) -> {
            List<String> declared = declaredActions.getOrDefault(resource, List.of());
            objectsOf(resourcePermissions).forEach(obj -> {
                List<ResourceAction> actions = obj
                        .getAllow()
                        .stream()
                        .filter(declared::contains)
                        .distinct()
                        .map(ResourceAction::findByCode)
                        .filter(action -> action.getAccessType() != ResourceAction.AccessType.NOT_GRANTABLE)
                        .sorted(Comparator.comparing(ResourceAction::getCode))
                        .toList();
                if (!actions.isEmpty()) {
                    objectActions.add(new ObjectActionsDto(resource, obj.getUuid(), actions));
                }
            });
        });
        return objectActions
                .stream()
                .sorted(Comparator
                        .comparing((ObjectActionsDto entry) -> entry.getResource().getCode())
                        .thenComparing(ObjectActionsDto::getObjectUuid))
                .toList();
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
