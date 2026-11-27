package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.ObjectPermissionsDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

/**
 * Decides which resources a user may list: those with a list grant on the resource or any of its objects, an owned
 * resource with a resource-level create grant, an owned resource of which the user owns an object or has one assigned
 * to a group they are a member of, and a group-assignable resource when they are a member of any group.
 */
@Component
public class ResourceListingRule {

    private static final List<Resource> DEFAULT_ALLOWED_LISTINGS = List.of(Resource.DASHBOARD, Resource.APPROVAL);

    private final ContextRefreshListener contextRefreshListener;
    private final OwnerAssociationRepository ownerAssociationRepository;

    public ResourceListingRule(ContextRefreshListener contextRefreshListener,
            OwnerAssociationRepository ownerAssociationRepository) {
        this.contextRefreshListener = contextRefreshListener;
        this.ownerAssociationRepository = ownerAssociationRepository;
    }

    public List<Resource> allowedListings(UserProfileDto userProfileDto) {
        List<Resource> allListings = listableResources();
        if (allowsAllResources(userProfileDto)) {
            return withDefaultListings(allListings);
        }

        Grants grants = Grants.of(userProfileDto);
        List<Resource> allowedListings = new ArrayList<>();
        List<Resource> associatedResourcesToCheck = new ArrayList<>();
        for (Resource resource : allListings) {
            Decision decision = grants.decide(resource);
            if (decision == Decision.ALLOWED) {
                allowedListings.add(resource);
            } else if (decision == Decision.IF_ASSOCIATED) {
                associatedResourcesToCheck.add(resource);
            }
        }
        allowedListings.addAll(findResourcesWithOwnedOrGroupAssignedObjects(associatedResourcesToCheck, grants));
        return withDefaultListings(allowedListings);
    }

    /** Whether {@code resource} is among {@link #allowedListings}, checking that resource alone. */
    public boolean canList(UserProfileDto userProfileDto, Resource resource) {
        if (DEFAULT_ALLOWED_LISTINGS.contains(resource)) {
            return true;
        }
        if (!listableResources().contains(resource)) {
            return false;
        }
        if (allowsAllResources(userProfileDto)) {
            return true;
        }
        Grants grants = Grants.of(userProfileDto);
        return switch (grants.decide(resource)) {
            case ALLOWED -> true;
            case IF_ASSOCIATED -> !findResourcesWithOwnedOrGroupAssignedObjects(List.of(resource), grants).isEmpty();
            case DENIED -> false;
        };
    }

    /** Shared with the allowed actions, so a change to how a grant is looked up reaches both. */
    public static Map<Resource, ResourcePermissionsDto> mapPermissionsByResource(UserProfileDto userProfileDto) {
        return userProfileDto
                .getPermissions()
                .getResources()
                .stream()
                .collect(Collectors.toMap(resource -> Resource.findByCode(resource.getName()), resource -> resource));
    }

    private List<Resource> listableResources() {
        return contextRefreshListener
                .getResources()
                .stream()
                .filter(syncResource -> syncResource.getActions().contains(ResourceAction.LIST.getCode()))
                .map(syncResource -> Resource.findByCode(syncResource.getName().getCode()))
                .sorted(Comparator.comparing(Resource::getCode))
                .toList();
    }

    private static boolean allowsAllResources(UserProfileDto userProfileDto) {
        return Boolean.TRUE.equals(userProfileDto.getPermissions().getAllowAllResources());
    }

    private enum Decision {
        ALLOWED,
        IF_ASSOCIATED,
        DENIED
    }

    private record Grants(UUID userUuid, Map<Resource, ResourcePermissionsDto> permissions,
            GroupMembership groupMembership) {

        static Grants of(UserProfileDto userProfileDto) {
            Map<Resource, ResourcePermissionsDto> permissions = mapPermissionsByResource(userProfileDto);
            return new Grants(UUID.fromString(userProfileDto.getUser().getUuid()), permissions,
                    GroupMembership.of(permissions.get(Resource.GROUP)));
        }

        Decision decide(Resource resource) {
            ResourcePermissionsDto resourcePermissions = permissions.get(resource);
            if (hasListGrant(resourcePermissions)
                    || resource.hasOwner() && hasResourceLevelAction(resourcePermissions, ResourceAction.CREATE)) {
                return Decision.ALLOWED;
            }
            if (resource.hasOwner()) {
                return Decision.IF_ASSOCIATED;
            }
            return resource.hasGroups() && groupMembership.any() ? Decision.ALLOWED : Decision.DENIED;
        }
    }

    private static boolean hasListGrant(ResourcePermissionsDto resourcePermissions) {
        return hasResourceLevelAction(resourcePermissions, ResourceAction.LIST)
                || resourcePermissions != null && objectsOf(resourcePermissions)
                        .anyMatch(obj -> obj.getAllow().contains(ResourceAction.LIST.getCode()));
    }

    private static boolean hasResourceLevelAction(ResourcePermissionsDto resourcePermissions, ResourceAction action) {
        return resourcePermissions != null && (Boolean.TRUE.equals(resourcePermissions.getAllowAllActions())
                || resourcePermissions.getActions() != null
                        && resourcePermissions.getActions().contains(action.getCode()));
    }

    private List<Resource> findResourcesWithOwnedOrGroupAssignedObjects(List<Resource> resources, Grants grants) {
        if (resources.isEmpty()) {
            return List.of();
        }
        GroupMembership groupMembership = grants.groupMembership();
        String resourceNames = resources.stream().map(Resource::name).collect(Collectors.joining(",", "{", "}"));
        return ownerAssociationRepository
                .findResourcesWithOwnedOrGroupAssignedObjects(resourceNames, grants.userUuid(),
                        groupMembership.allGroups(), toArrayLiteral(groupMembership.groupUuids()),
                        toArrayLiteral(groupMembership.deniedGroupUuids()))
                .stream()
                .map(Resource::valueOf)
                .toList();
    }

    private static String toArrayLiteral(Set<UUID> uuids) {
        return uuids.stream().map(UUID::toString).collect(Collectors.joining(",", "{", "}"));
    }

    /**
     * The groups on which the user holds the members action: an object assigned to one of them is listable and viewable
     * by the user. A group on which the action is denied is excluded however it was granted, as the authorization
     * service excludes it.
     */
    private record GroupMembership(boolean allGroups, Set<UUID> groupUuids, Set<UUID> deniedGroupUuids) {

        static GroupMembership of(ResourcePermissionsDto groupPermissions) {
            if (groupPermissions == null) {
                return new GroupMembership(false, Set.of(), Set.of());
            }
            boolean allGroups = hasResourceLevelAction(groupPermissions, ResourceAction.MEMBERS);
            Set<UUID> deniedGroupUuids = groupUuidsWhere(groupPermissions, ObjectPermissionsDto::getDeny);
            Set<UUID> groupUuids = groupUuidsWhere(groupPermissions, ObjectPermissionsDto::getAllow);
            groupUuids.removeAll(deniedGroupUuids);
            return new GroupMembership(allGroups, groupUuids, deniedGroupUuids);
        }

        private static Set<UUID> groupUuidsWhere(ResourcePermissionsDto groupPermissions,
                Function<ObjectPermissionsDto, List<String>> actions) {
            return objectsOf(groupPermissions).filter(obj -> {
                List<String> objectActions = actions.apply(obj);
                return objectActions != null && objectActions.contains(ResourceAction.MEMBERS.getCode());
            }).flatMap(obj -> parseUuid(obj.getUuid())).collect(Collectors.toCollection(HashSet::new));
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

    private static List<Resource> withDefaultListings(List<Resource> listings) {
        return Stream
                .concat(listings.stream(),
                        DEFAULT_ALLOWED_LISTINGS.stream().filter(defaultListing -> !listings.contains(defaultListing)))
                .sorted(Comparator.comparing(Resource::getCode))
                .toList();
    }
}
