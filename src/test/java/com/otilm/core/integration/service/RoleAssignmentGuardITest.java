package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.RoleWithPaginationDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.LocalAdminExternalService;
import com.otilm.core.service.RoleManagementExternalService;
import com.otilm.core.service.UserManagementExternalService;
import com.otilm.core.service.UserManagementInternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ManagementApiMocks;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers the guard that decides which roles may be attached to which users, from both directions: role -> users
 * ({@link RoleManagementExternalService#updateUsers}) and user -> roles
 * ({@link UserManagementExternalService#updateRoles} / {@code updateRole}).
 */
@Import(ManagementApiMocks.class)
class RoleAssignmentGuardITest extends BaseSpringBootTest {

    private static final String HUMAN_USERNAME = "operator";

    @Autowired
    private RoleManagementExternalService roleManagementService;

    @Autowired
    private UserManagementExternalService userManagementService;

    @Autowired
    private UserManagementInternalService userManagementInternalService;

    @Autowired
    private LocalAdminExternalService localAdminService;

    @Autowired
    private RoleManagementApiClient roleManagementApiClient;

    @Autowired
    private UserManagementApiClient userManagementApiClient;

    @MockitoBean
    private AuthenticationCache authenticationCache;

    // Rule 1: a role paired with a system user is never assignable to a human user.

    /**
     * Membership updates replace the whole list, so a caller could otherwise detach the system user first and attach a
     * human on a second call, once the role no longer looks paired.
     */
    @Test
    void updateUsers_rejectsDetachingTheSystemUserFromItsRole() {
        String roleUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(
                        role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(systemUser(AuthHelper.ACME_USERNAME))));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> roleManagementService.updateUsers(roleUuid, List.of()));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(roleManagementApiClient, never()).updateUsers(any(), any());
    }

    @Test
    void updateUsers_rejectsHumanUserOnRolePairedWithSystemUser() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(
                        role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(systemUser(AuthHelper.ACME_USERNAME))));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        List<String> members = List.of(humanUuid);

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> roleManagementService.updateUsers(roleUuid, members));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        Assertions.assertTrue(exception.getMessage().contains(HUMAN_USERNAME), exception.getMessage());
        verify(roleManagementApiClient, never()).updateUsers(any(), any());
    }

    @Test
    void updateRole_rejectsRolePairedWithSystemUserForHumanUser() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(
                        role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(systemUser(AuthHelper.ACME_USERNAME))));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRole(humanUuid, roleUuid));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(userManagementApiClient, never()).updateRole(any(), any());
    }

    /** A request that omits the list entirely asks for the same thing an empty one does: no members remain. */
    @Test
    void updateUsers_treatsAnAbsentMemberListAsRemovingEveryone() {
        String roleUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(
                        role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(systemUser(AuthHelper.ACME_USERNAME))));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> roleManagementService.updateUsers(roleUuid, null));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(roleManagementApiClient, never()).updateUsers(any(), any());
    }

    @Test
    void updateRoles_treatsAnAbsentRoleListAsClearingThem() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserHolding(acmeUuid, AuthHelper.ACME_USERNAME, roleUuid, AuthHelper.ACME_USERNAME));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRoles(acmeUuid, null));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(userManagementApiClient, never()).updateRoles(any(), any());
    }

    // Rule 1b: a system user holds its own role and nothing else — otherwise a ROLE:UPDATE holder could widen a
    // protocol identity by adding it to a role that grants more than the protocol needs.

    @Test
    void updateUsers_rejectsAttachingASystemUserToAnotherRole() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(role(roleUuid, "operators", false, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(false));
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserDetail(acmeUuid, AuthHelper.ACME_USERNAME));
        List<String> members = List.of(acmeUuid);

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> roleManagementService.updateUsers(roleUuid, members));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(roleManagementApiClient, never()).updateUsers(any(), any());
    }

    @Test
    void updateRole_rejectsGivingAnotherRoleToASystemUser() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(role(roleUuid, "operators", false, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(false));
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserDetail(acmeUuid, AuthHelper.ACME_USERNAME));

        Assertions.assertThrows(ValidationException.class, () -> userManagementService.updateRole(acmeUuid, roleUuid));

        verify(userManagementApiClient, never()).updateRole(any(), any());
    }

    @Test
    void updateUsers_allowsTheSystemUserToStayOnItsOwnRole() {
        String roleUuid = UUID.randomUUID().toString();
        UserDto acme = systemUser(AuthHelper.ACME_USERNAME);
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(acme)));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(false));
        when(roleManagementApiClient.updateUsers(eq(roleUuid), any()))
                .thenReturn(role(roleUuid, AuthHelper.ACME_USERNAME, true, List.of(acme)));

        roleManagementService.updateUsers(roleUuid, List.of(acme.getUuid()));

        verify(roleManagementApiClient).updateUsers(roleUuid, List.of(acme.getUuid()));
    }

    // The all-resources rule is about granting. A role the user already holds, or a member already in the role, is
    // not being granted anything, and updateRoles replaces the whole list so a role-picker always resends them.

    @Test
    void updateRoles_allowsAddingARoleWhileRetainingAnAllResourcesRoleTheUserAlreadyHolds() {
        String superadminUuid = UUID.randomUUID().toString();
        String operatorsUuid = UUID.randomUUID().toString();
        String targetUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(superadminUuid))
                .thenReturn(role(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(superadminUuid)).thenReturn(permissions(true));
        when(roleManagementApiClient.getRoleDetail(operatorsUuid))
                .thenReturn(role(operatorsUuid, "operators", false, List.of()));
        when(roleManagementApiClient.getPermissions(operatorsUuid)).thenReturn(permissions(false));
        when(userManagementApiClient.getUserDetail(targetUuid))
                .thenReturn(humanUserHolding(targetUuid, superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME));
        when(userManagementApiClient.updateRoles(eq(targetUuid), any())).thenReturn(humanUser(targetUuid));

        userManagementService.updateRoles(targetUuid, List.of(superadminUuid, operatorsUuid));

        verify(userManagementApiClient).updateRoles(targetUuid, List.of(superadminUuid, operatorsUuid));
    }

    @Test
    void updateUsers_allowsRemovingAMemberFromAnAllResourcesRoleWithoutHoldingIt() {
        String superadminUuid = UUID.randomUUID().toString();
        UserDto keptMember = humanMember("kept");
        UserDto removedMember = humanMember("removed");
        when(roleManagementApiClient.getRoleDetail(superadminUuid))
                .thenReturn(role(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true,
                        List.of(keptMember, removedMember)));
        when(roleManagementApiClient.getPermissions(superadminUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(keptMember.getUuid())).thenReturn(humanUser(keptMember.getUuid()));
        when(roleManagementApiClient.updateUsers(eq(superadminUuid), any()))
                .thenReturn(role(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of(keptMember)));

        roleManagementService.updateUsers(superadminUuid, List.of(keptMember.getUuid()));

        verify(roleManagementApiClient).updateUsers(superadminUuid, List.of(keptMember.getUuid()));
    }

    // Rule 1c: a system user keeps the role it holds. updateRoles replaces the whole list and removeRole detaches
    // one, so both can strand the identity even though neither assigns anything.

    @Test
    void updateRoles_rejectsClearingTheRolesOfASystemUser() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserHolding(acmeUuid, AuthHelper.ACME_USERNAME, roleUuid, AuthHelper.ACME_USERNAME));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRoles(acmeUuid, List.of()));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(userManagementApiClient, never()).updateRoles(any(), any());
    }

    @Test
    void removeRole_rejectsDetachingTheRoleOfASystemUser() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserHolding(acmeUuid, AuthHelper.ACME_USERNAME, roleUuid, AuthHelper.ACME_USERNAME));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.removeRole(acmeUuid, roleUuid));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(userManagementApiClient, never()).removeRole(any(), any());
    }

    @Test
    void removeRole_allowsDetachingARoleFromAHumanUser() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        when(userManagementApiClient.removeRole(humanUuid, roleUuid)).thenReturn(humanUser(humanUuid));

        userManagementService.removeRole(humanUuid, roleUuid);

        verify(userManagementApiClient).removeRole(humanUuid, roleUuid);
    }

    @Test
    void updateRoles_allowsASystemUserToKeepItsOwnRole() {
        String roleUuid = UUID.randomUUID().toString();
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserHolding(acmeUuid, AuthHelper.ACME_USERNAME, roleUuid, AuthHelper.ACME_USERNAME));
        when(userManagementApiClient.updateRoles(eq(acmeUuid), any())).thenReturn(humanUser(acmeUuid));
        List<String> retained = List.of(roleUuid);

        userManagementService.updateRoles(acmeUuid, retained);

        verify(userManagementApiClient).updateRoles(acmeUuid, retained);
    }

    // Rule 2: a role that allows all resources may only be assigned by someone who already holds it.

    @Test
    void updateRoles_rejectsAllowAllResourcesRoleWhenCallerDoesNotHoldIt() {
        String roleUuid = UUID.randomUUID().toString();
        String targetUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(true));

        List<String> granted = List.of(roleUuid);

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRoles(targetUuid, granted));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.SUPERADMIN_ROLE_NAME), exception.getMessage());
        verify(userManagementApiClient, never()).updateRoles(any(), any());
    }

    @Test
    void updateRoles_allowsACallerHoldingAllResourcesToGrantAnAllResourcesRole() {
        String superadminUuid = UUID.randomUUID().toString();
        String adminUuid = UUID.randomUUID().toString();
        String targetUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(adminUuid)).thenReturn(role(adminUuid, "admin", true, List.of()));
        when(roleManagementApiClient.getPermissions(adminUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(targetUuid)).thenReturn(humanUser(targetUuid));
        when(userManagementApiClient.updateRoles(eq(targetUuid), any())).thenReturn(humanUser(targetUuid));
        authenticateHoldingAllResources(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME);
        List<String> granted = List.of(adminUuid);

        userManagementService.updateRoles(targetUuid, granted);

        verify(userManagementApiClient).updateRoles(targetUuid, granted);
    }

    /** The role side of the same rule: adding a member is the grant, and a caller holding everything may make it. */
    @Test
    void updateUsers_allowsACallerHoldingAllResourcesToAddAMember() {
        String adminUuid = UUID.randomUUID().toString();
        String superadminUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(adminUuid)).thenReturn(role(adminUuid, "admin", true, List.of()));
        when(roleManagementApiClient.getPermissions(adminUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        when(roleManagementApiClient.updateUsers(eq(adminUuid), any()))
                .thenReturn(role(adminUuid, "admin", true, List.of()));
        authenticateHoldingAllResources(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME);
        List<String> members = List.of(humanUuid);

        roleManagementService.updateUsers(adminUuid, members);

        verify(roleManagementApiClient).updateUsers(adminUuid, members);
    }

    /** A caller the platform cannot resolve holds nothing, so it is refused rather than treated as privileged. */
    @Test
    void updateRoles_rejectsAnAllResourcesRoleWhenTheCallerCannotBeResolved() {
        String roleUuid = UUID.randomUUID().toString();
        String targetUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(targetUuid)).thenReturn(humanUser(targetUuid));
        authenticateWithUnreadableProfile();
        List<String> granted = List.of(roleUuid);

        Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRoles(targetUuid, granted));

        verify(userManagementApiClient, never()).updateRoles(any(), any());
    }

    /** A caller carrying no permissions at all is not the same as one carrying all of them. */
    @Test
    void updateRoles_rejectsAnAllResourcesRoleWhenTheCallerCarriesNoPermissions() {
        String roleUuid = UUID.randomUUID().toString();
        String targetUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(targetUuid)).thenReturn(humanUser(targetUuid));
        authenticateWithoutPermissions();
        List<String> granted = List.of(roleUuid);

        Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.updateRoles(targetUuid, granted));

        verify(userManagementApiClient, never()).updateRoles(any(), any());
    }

    @Test
    void updateUsers_rejectsAllowAllResourcesRoleWhenCallerDoesNotHoldIt() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(true));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));

        List<String> members = List.of(humanUuid);

        Assertions.assertThrows(ValidationException.class, () -> roleManagementService.updateUsers(roleUuid, members));

        verify(roleManagementApiClient, never()).updateUsers(any(), any());
    }

    // Rule 3: every other role - auditor included, system role though it is - stays assignable.

    @Test
    void updateRole_allowsAuditorSystemRole() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(roleManagementApiClient.getRoleDetail(roleUuid))
                .thenReturn(role(roleUuid, AuthHelper.AUDITOR_ROLE_NAME, true, List.of()));
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(false));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        when(userManagementApiClient.updateRole(humanUuid, roleUuid)).thenReturn(humanUser(humanUuid));

        userManagementService.updateRole(humanUuid, roleUuid);

        verify(userManagementApiClient).updateRole(humanUuid, roleUuid);
    }

    @Test
    void updateUsers_allowsAuditorSystemRole() {
        String roleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        RoleDetailDto auditorRole = role(roleUuid, AuthHelper.AUDITOR_ROLE_NAME, true, List.of());
        when(roleManagementApiClient.getRoleDetail(roleUuid)).thenReturn(auditorRole);
        when(roleManagementApiClient.getPermissions(roleUuid)).thenReturn(permissions(false));
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        when(roleManagementApiClient.updateUsers(eq(roleUuid), any())).thenReturn(auditorRole);

        roleManagementService.updateUsers(roleUuid, List.of(humanUuid));

        verify(roleManagementApiClient).updateUsers(roleUuid, List.of(humanUuid));
    }

    // A system user's account state is as load-bearing as its role: disabling acme stops ACME enrolment just as
    // surely as detaching its role would.

    @Test
    void disableUser_rejectsDisablingASystemUser() {
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserDetail(acmeUuid, AuthHelper.ACME_USERNAME));

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> userManagementService.disableUser(acmeUuid));

        Assertions.assertTrue(exception.getMessage().contains(AuthHelper.ACME_USERNAME), exception.getMessage());
        verify(userManagementApiClient, never()).disableUser(any());
    }

    @Test
    void enableUser_rejectsEnablingASystemUser() {
        String acmeUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(acmeUuid))
                .thenReturn(systemUserDetail(acmeUuid, AuthHelper.ACME_USERNAME));

        Assertions.assertThrows(ValidationException.class, () -> userManagementService.enableUser(acmeUuid));

        verify(userManagementApiClient, never()).enableUser(any());
    }

    /**
     * enableUser is the permit case because disableUser also clears session state, which this context has no table for.
     */
    @Test
    void enableUser_allowsEnablingAHumanUser() {
        String humanUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.getUserDetail(humanUuid)).thenReturn(humanUser(humanUuid));
        when(userManagementApiClient.enableUser(humanUuid)).thenReturn(humanUser(humanUuid));

        userManagementService.enableUser(humanUuid);

        verify(userManagementApiClient).enableUser(humanUuid);
    }

    @Test
    void createUser_grantsSuperadminToTheFirstAdministrator() throws Exception {
        String superadminUuid = UUID.randomUUID().toString();
        String createdUuid = UUID.randomUUID().toString();
        RoleWithPaginationDto roles = new RoleWithPaginationDto();
        roles
                .setData(List
                        .of(namedRole(UUID.randomUUID().toString(), AuthHelper.SUPERADMIN_ROLE_NAME, false),
                                namedRole(UUID.randomUUID().toString(), "operators", true),
                                namedRole(superadminUuid, AuthHelper.SUPERADMIN_ROLE_NAME, true)));
        when(roleManagementApiClient.getRoles()).thenReturn(roles);
        when(userManagementApiClient.createUser(any())).thenReturn(humanUser(createdUuid));
        when(userManagementApiClient.updateRole(createdUuid, superadminUuid)).thenReturn(humanUser(createdUuid));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("first-admin");

        localAdminService.createUser(request);

        verify(userManagementApiClient).updateRole(createdUuid, superadminUuid);
    }

    /** The role is resolved before the user is created, so a missing one strands no half-made administrator. */
    @Test
    void createUser_failsWithoutCreatingAUserWhenTheSuperadminRoleIsMissing() {
        RoleWithPaginationDto noRoles = new RoleWithPaginationDto();
        noRoles.setData(List.of());
        when(roleManagementApiClient.getRoles()).thenReturn(noRoles);
        AddUserRequestDto request = new AddUserRequestDto();

        Assertions.assertThrows(NotFoundException.class, () -> localAdminService.createUser(request));

        verify(userManagementApiClient, never()).createUser(any());
    }

    /**
     * The first administrator is created by the localhost identity, which holds no roles at all, so the rule that an
     * all-resources role may only be granted by a holder would refuse every fresh install if the bootstrap went through
     * the guarded path.
     */
    @Test
    void updateRoleInternal_bypassesTheGuardSoTheFirstAdministratorCanBeCreated() {
        String superadminRoleUuid = UUID.randomUUID().toString();
        String humanUuid = UUID.randomUUID().toString();
        when(userManagementApiClient.updateRole(humanUuid, superadminRoleUuid)).thenReturn(humanUser(humanUuid));

        userManagementInternalService.updateRoleInternal(humanUuid, superadminRoleUuid);

        verify(userManagementApiClient).updateRole(humanUuid, superadminRoleUuid);
        verify(roleManagementApiClient, never()).getRoleDetail(any());
    }

    /** Rawdata the profile cannot be parsed from, which is how an unresolvable caller presents itself. */
    private void authenticateWithUnreadableProfile() {
        setAuthentication("not-a-profile");
    }

    private void authenticateWithoutPermissions() {
        UserProfileDto profile = callerProfile();
        profile.setRoles(List.of());
        setAuthentication(writeProfile(profile));
    }

    /** A caller whose permissions cover everything, as superadmin's and admin's do. */
    private void authenticateHoldingAllResources(String roleUuid, String roleName) {
        UserProfileDto profile = callerProfile();
        profile.setRoles(List.of(new NameAndUuidDto(roleUuid, roleName)));
        profile.setPermissions(permissions(true));
        setAuthentication(writeProfile(profile));
    }

    private static UserProfileDto callerProfile() {
        UserProfileDto profile = new UserProfileDto();
        UserDto caller = new UserDto();
        caller.setUuid(UUID.randomUUID().toString());
        caller.setUsername("tst-user");
        profile.setUser(caller);
        return profile;
    }

    private static String writeProfile(UserProfileDto profile) {
        try {
            return new ObjectMapper().writeValueAsString(profile);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void setAuthentication(String rawData) {
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, UUID.randomUUID().toString(),
                "tst-user", List.of(), rawData);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }

    private static RoleDetailDto role(String uuid, String name, boolean systemRole, List<UserDto> users) {
        RoleDetailDto dto = new RoleDetailDto();
        dto.setUuid(uuid);
        dto.setName(name);
        dto.setSystemRole(systemRole);
        dto.setUsers(users);
        return dto;
    }

    private static SubjectPermissionsDto permissions(boolean allowAllResources) {
        SubjectPermissionsDto dto = new SubjectPermissionsDto();
        dto.setAllowAllResources(allowAllResources);
        dto.setResources(List.of());
        return dto;
    }

    private static RoleDto namedRole(String uuid, String name, boolean systemRole) {
        RoleDto dto = new RoleDto();
        dto.setUuid(uuid);
        dto.setName(name);
        dto.setSystemRole(systemRole);
        return dto;
    }

    private static UserDto humanMember(String username) {
        UserDto dto = new UserDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setUsername(username);
        dto.setSystemUser(false);
        return dto;
    }

    private static UserDetailDto humanUserHolding(String uuid, String roleUuid, String roleName) {
        UserDetailDto dto = humanUser(uuid);
        RoleDto role = new RoleDto();
        role.setUuid(roleUuid);
        role.setName(roleName);
        dto.setRoles(List.of(role));
        return dto;
    }

    private static UserDto systemUser(String username) {
        UserDto dto = new UserDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setUsername(username);
        dto.setSystemUser(true);
        return dto;
    }

    private static UserDetailDto systemUserHolding(String uuid, String username, String roleUuid, String roleName) {
        UserDetailDto dto = systemUserDetail(uuid, username);
        RoleDto role = new RoleDto();
        role.setUuid(roleUuid);
        role.setName(roleName);
        dto.setRoles(List.of(role));
        return dto;
    }

    private static UserDetailDto systemUserDetail(String uuid, String username) {
        UserDetailDto dto = new UserDetailDto();
        dto.setUuid(uuid);
        dto.setUsername(username);
        dto.setSystemUser(true);
        dto.setRoles(List.of());
        return dto;
    }

    private static UserDetailDto humanUser(String uuid) {
        UserDetailDto dto = new UserDetailDto();
        dto.setUuid(uuid);
        dto.setUsername(HUMAN_USERNAME);
        dto.setSystemUser(false);
        dto.setRoles(List.of());
        return dto;
    }
}
