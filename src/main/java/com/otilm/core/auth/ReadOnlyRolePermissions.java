package com.otilm.core.auth;

import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.ResourcePermissionsRequestDto;
import com.otilm.api.model.core.auth.RolePermissionsRequestDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Derives the permission set of a role that may read everything and change nothing, so a newly annotated resource or
 * action lands on the right side of the boundary without anyone remembering this role. Kept free of Spring and of the
 * auth client, because this is the half where a mistake silently grants write access.
 */
public final class ReadOnlyRolePermissions {

    /**
     * Taken from {@link ResourceAction#isGrantableToReadOnlyRole()}, so classifying a new action on the enum is the
     * only step needed. A code absent here is a write, a sensitive read, a sentinel, or unknown to this version.
     */
    private static final Set<String> READ_ONLY_ACTION_CODES = Arrays
            .stream(ResourceAction.values())
            .filter(ResourceAction::isGrantableToReadOnlyRole)
            .map(ResourceAction::getCode)
            .collect(Collectors.toUnmodifiableSet());

    private ReadOnlyRolePermissions() {
    }

    /** Derives the payload from the catalogue the startup annotation scan produced. */
    public static RolePermissionsRequestDto deriveFrom(List<ResourceSyncRequestDto> catalogue) {
        Map<String, List<String>> actionCodesByResource = new LinkedHashMap<>();
        for (ResourceSyncRequestDto scanned : catalogue) {
            actionCodesByResource
                    .put(scanned.getName().getCode(), scanned.getActions() == null ? List.of() : scanned.getActions());
        }
        return derive(actionCodesByResource);
    }

    /**
     * A resource left with no grantable action is dropped, not emitted with an empty action list: an empty list reads
     * as every action on that resource, the exact inverse of a read-only grant. Actions are deduplicated and sorted so
     * an unchanged catalogue yields an identical payload whatever order it arrived in.
     */
    private static RolePermissionsRequestDto derive(Map<String, List<String>> actionCodesByResource) {
        List<ResourcePermissionsRequestDto> resources = new ArrayList<>();
        actionCodesByResource.forEach((resourceCode, actionCodes) -> {
            List<String> granted = actionCodes
                    .stream()
                    .filter(READ_ONLY_ACTION_CODES::contains)
                    .distinct()
                    .sorted(Comparator.naturalOrder())
                    .toList();
            if (!granted.isEmpty()) {
                resources.add(readOnlyGrant(resourceCode, granted));
            }
        });

        RolePermissionsRequestDto derived = new RolePermissionsRequestDto();
        derived.setAllowAllResources(false);
        derived.setResources(resources);
        return derived;
    }

    /**
     * Compares grants rather than payloads: action order is the auth service's own and means nothing, while an
     * object-level entry — which the derivation never emits — is a grant that has to go.
     */
    public static boolean matches(RolePermissionsRequestDto derived, SubjectPermissionsDto stored) {
        if (stored == null) {
            return false;
        }
        if (Boolean.TRUE.equals(derived.getAllowAllResources()) != Boolean.TRUE.equals(stored.getAllowAllResources())) {
            return false;
        }

        Map<String, String> derivedGrants = new TreeMap<>();
        for (ResourcePermissionsRequestDto resource : derived.getResources()) {
            derivedGrants
                    .put(resource.getName(), grantSignature(resource.getAllowAllActions(), resource.getActions(),
                            resource.getObjects()));
        }
        Map<String, String> storedGrants = new TreeMap<>();
        // A remote DTO can arrive with the list absent rather than empty, which is the same thing: no grants.
        for (ResourcePermissionsDto resource : stored.getResources() == null
                ? List.<ResourcePermissionsDto>of()
                : stored.getResources()) {
            storedGrants
                    .put(resource.getName(), grantSignature(resource.getAllowAllActions(), resource.getActions(),
                            resource.getObjects()));
        }
        return derivedGrants.equals(storedGrants);
    }

    public static int countActions(RolePermissionsRequestDto permissions) {
        return permissions.getResources().stream().mapToInt(resource -> resource.getActions().size()).sum();
    }

    private static String grantSignature(Boolean allowAllActions, List<String> actions, List<?> objects) {
        List<String> sortedActions = actions == null ? List.of() : actions.stream().sorted().toList();
        String actionSignature = Boolean.TRUE.equals(allowAllActions) ? "*" : String.join(",", sortedActions);
        return objects == null || objects.isEmpty() ? actionSignature : actionSignature + "+objects";
    }

    private static ResourcePermissionsRequestDto readOnlyGrant(String resourceName, List<String> actions) {
        ResourcePermissionsRequestDto permissions = new ResourcePermissionsRequestDto();
        permissions.setName(resourceName);
        permissions.setAllowAllActions(false);
        permissions.setActions(actions);
        permissions.setObjects(List.of());
        return permissions;
    }
}
