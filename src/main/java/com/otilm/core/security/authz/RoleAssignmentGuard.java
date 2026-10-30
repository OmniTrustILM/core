package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Decides which roles may be attached to which users. Membership is editable from both directions, so both enforce the
 * same rules — otherwise the weaker endpoint is the way around the stronger one. A role paired with a system user is
 * refused, as is a role granting all resources unless the caller already holds all resources itself; without the
 * latter, {@code USER:UPDATE} alone would grant full platform administration. Everything else, {@code auditor}
 * included, stays assignable.
 */
@Component
public class RoleAssignmentGuard {

    private RoleManagementApiClient roleManagementApiClient;
    private UserManagementApiClient userManagementApiClient;

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    /** Guards the role -&gt; users direction: the users that would end up holding {@code roleUuid}. */
    public void checkUsersAssignableToRole(String roleUuid, List<String> userUuids) {
        List<String> members = userUuids == null ? List.of() : userUuids;
        RoleDetailDto role = roleManagementApiClient.getRoleDetail(roleUuid);
        checkMembers(role, members);
        if (addsAMember(role, members) && grantsAllResources(roleUuid)) {
            requireCallerHoldsAllResources(role);
        }
        if (isPairedWithSystemUser(role)) {
            requireSystemMembersRetained(role, members);
        }
    }

    /** Guards the user -&gt; roles direction: the roles that would end up held by {@code userUuid}. */
    public void checkRolesAssignableToUser(String userUuid, List<String> roleUuids) {
        if (roleUuids == null || roleUuids.isEmpty()) {
            return;
        }
        Set<String> alreadyHeld = heldRoleUuids(userUuid);

        for (String roleUuid : roleUuids) {
            // A replacement resends every role the user keeps, and keeping one grants nothing.
            if (alreadyHeld.contains(roleUuid)) {
                continue;
            }
            RoleDetailDto role = roleManagementApiClient.getRoleDetail(roleUuid);
            checkMembers(role, List.of(userUuid));
            if (grantsAllResources(roleUuid)) {
                requireCallerHoldsAllResources(role);
            }
        }
    }

    /**
     * Only an added member is being granted the role. Keeping the members a role already has, or dropping some of them,
     * grants nobody anything — and refusing a removal would be stricter than the rule it enforces.
     */
    private static boolean addsAMember(RoleDetailDto role, List<String> members) {
        Set<String> current = role.getUsers() == null
                ? Set.of()
                : role.getUsers().stream().map(UserDto::getUuid).collect(Collectors.toSet());
        return members.stream().anyMatch(member -> !current.contains(member));
    }

    private Set<String> heldRoleUuids(String userUuid) {
        UserDetailDto user = userManagementApiClient.getUserDetail(userUuid);
        if (user == null || user.getRoles() == null) {
            return Set.of();
        }
        return user.getRoles().stream().map(RoleDto::getUuid).collect(Collectors.toSet());
    }

    /**
     * Guards a replacement of a user's roles: a system user must keep the role it holds. Assigning nothing is still a
     * detachment, so an empty list has to be refused rather than skipped.
     */
    public void checkRolesRetainedForUser(String userUuid, List<String> retainedRoleUuids) {
        List<String> retained = retainedRoleUuids == null ? List.of() : retainedRoleUuids;
        rejectStrandingSystemUser(userUuid, held -> !retained.contains(held.getUuid()));
    }

    /** Guards an explicit removal, which detaches without assigning anything the other rules could inspect. */
    public void checkRoleRemovableFromUser(String userUuid, String roleUuid) {
        rejectStrandingSystemUser(userUuid, held -> held.getUuid().equals(roleUuid));
    }

    /**
     * The pairing between a system user and its role is that identity's permission boundary. Stranding it leaves the
     * identity unable to do the job it exists for, and unpairs the role so the rules above stop recognising it.
     */
    private void rejectStrandingSystemUser(String userUuid, Predicate<RoleDto> losesRole) {
        UserDetailDto user = userManagementApiClient.getUserDetail(userUuid);
        if (!isSystemUser(user) || user.getRoles() == null) {
            return;
        }
        for (RoleDto held : user.getRoles()) {
            if (losesRole.test(held)) {
                throw new ValidationException("Role '%s' belongs to system user '%s' and cannot be removed from it."
                        .formatted(held.getName(), user.getUsername()));
            }
        }
    }

    /**
     * A system user holds the role seeded with it and no other, and that role takes no other members: the pairing is
     * the identity's whole permission boundary, so an editable half either widens it or hands it to an operator.
     */
    private void checkMembers(RoleDetailDto role, List<String> userUuids) {
        Set<String> systemMembers = systemMemberUuids(role);

        for (String userUuid : userUuids) {
            if (systemMembers.contains(userUuid)) {
                continue;
            }
            UserDetailDto user = userManagementApiClient.getUserDetail(userUuid);
            if (isSystemUser(user)) {
                throw new ValidationException(
                        "System user '%s' holds only its own role and cannot be added to role '%s'."
                                .formatted(user.getUsername(), role.getName()));
            }
            if (!systemMembers.isEmpty()) {
                throw new ValidationException("Role '%s' belongs to a system user and cannot be assigned to user '%s'."
                        .formatted(role.getName(), user.getUsername()));
            }
        }
    }

    private static Set<String> systemMemberUuids(RoleDetailDto role) {
        if (role.getUsers() == null) {
            return Set.of();
        }
        return role
                .getUsers()
                .stream()
                .filter(RoleAssignmentGuard::isSystemUser)
                .map(UserDto::getUuid)
                .collect(Collectors.toSet());
    }

    /**
     * A membership update replaces the whole list, so an omitted system user is a detached one — stranding that
     * identity and unpairing the role, leaving the rule above nothing to recognise on a second call.
     */
    private static void requireSystemMembersRetained(RoleDetailDto role, List<String> userUuids) {
        for (UserDto member : role.getUsers()) {
            if (isSystemUser(member) && !userUuids.contains(member.getUuid())) {
                throw new ValidationException("Role '%s' belongs to system user '%s', which cannot be removed from it."
                        .formatted(role.getName(), member.getUsername()));
            }
        }
    }

    /**
     * Read from the auth service rather than a hardcoded name list, so roles seeded alongside a system user are
     * recognised while {@code superadmin} — a system role carrying no system user — stays assignable.
     */
    private static boolean isPairedWithSystemUser(RoleDetailDto role) {
        return role.getUsers() != null && role.getUsers().stream().anyMatch(RoleAssignmentGuard::isSystemUser);
    }

    private boolean grantsAllResources(String roleUuid) {
        SubjectPermissionsDto permissions = roleManagementApiClient.getPermissions(roleUuid);
        return permissions != null && Boolean.TRUE.equals(permissions.getAllowAllResources());
    }

    /**
     * A caller who already holds every resource gains nothing by granting one, so superadmin is not confined to handing
     * out superadmin. Holding the role itself needs no separate check: the auth service merges every role's permissions
     * into the profile, so holding an all-resources role already sets the flag this reads.
     */
    private static void requireCallerHoldsAllResources(RoleDetailDto role) {
        if (!callerHoldsAllResources()) {
            throw new ValidationException(
                    "Role '%s' grants access to all resources and can only be assigned by a user who holds all"
                            .formatted(role.getName()) + " resources.");
        }
    }

    /** An unidentifiable caller holds nothing, so it is refused like any other caller without the permission. */
    private static boolean callerHoldsAllResources() {
        SubjectPermissionsDto permissions;
        try {
            permissions = AuthHelper.getUserProfile().getPermissions();
        } catch (ValidationException e) {
            return false;
        }
        return permissions != null && Boolean.TRUE.equals(permissions.getAllowAllResources());
    }

    private static boolean isSystemUser(UserDto user) {
        return user != null && Boolean.TRUE.equals(user.getSystemUser());
    }
}
