package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import java.util.List;

/**
 * Builds the user-profile JSON the platform hands OPA as {@code input.principal}, from the same DTOs the auth service
 * returns. A hand-written profile drifts from the real shape the moment one of those DTOs gains or renames a field, and
 * a test built on the drifted shape keeps passing while the production key changes underneath it.
 *
 * <p>
 * The profile builders return the DTO so a test can vary one field — the roles, the username, the permissions — and
 * serialize it with {@link #principal(UserProfileDto)}.
 */
public final class PrincipalFixtures {

    private static final String ANONYMOUS_USERNAME = "anonymousUser";

    private PrincipalFixtures() {
    }

    /** A caller who may read and list certificates and nothing else. */
    public static String operator(String uuid, String username) {
        return principal(operatorProfile(uuid, username));
    }

    /** A caller whose permissions allow every resource. */
    public static String admin(String uuid, String username) {
        return principal(adminProfile(uuid, username));
    }

    /** The unauthenticated pseudo-user, which carries a username but no permissions. */
    public static String anonymous() {
        return principal(anonymousProfile());
    }

    public static UserProfileDto operatorProfile(String uuid, String username) {
        ResourcePermissionsDto certificates = new ResourcePermissionsDto();
        certificates.setName("certificates");
        certificates.setAllowAllActions(false);
        certificates.setActions(List.of("detail", "list"));
        certificates.setObjects(List.of());
        return profile(uuid, username, permissions(false, List.of(certificates)));
    }

    public static UserProfileDto adminProfile(String uuid, String username) {
        return profile(uuid, username, permissions(true, List.of()));
    }

    public static UserProfileDto anonymousProfile() {
        return profile(null, ANONYMOUS_USERNAME, null);
    }

    public static String principal(UserProfileDto profile) {
        try {
            return new ObjectMapper().writeValueAsString(profile);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("A user profile fixture has to serialize", e);
        }
    }

    private static UserProfileDto profile(String uuid, String username, SubjectPermissionsDto permissions) {
        UserDto user = new UserDto();
        user.setUuid(uuid);
        user.setUsername(username);
        user.setEnabled(true);

        UserProfileDto profile = new UserProfileDto();
        profile.setUser(user);
        profile.setRoles(List.of());
        profile.setPermissions(permissions);
        return profile;
    }

    private static SubjectPermissionsDto permissions(boolean allowAllResources,
            List<ResourcePermissionsDto> resources) {
        SubjectPermissionsDto permissions = new SubjectPermissionsDto();
        permissions.setAllowAllResources(allowAllResources);
        permissions.setResources(resources);
        return permissions;
    }
}
