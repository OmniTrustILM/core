package com.otilm.core.auth;

import com.otilm.api.model.core.auth.ObjectPermissionsDto;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.RolePermissionsRequestDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.core.model.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReadOnlyRolePermissionsTest {

    /**
     * The auth service reads an empty action list together with {@code allowAllActions} as "every action on this
     * resource", so a resource that contributes no read action has to disappear from the payload rather than be emitted
     * empty - emitting it would grant the read-only role every write on that resource.
     */
    @Test
    void omitsResourceWhoseActionsAreAllNonGrantable() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.CREATE, ResourceAction.DELETE));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(derived.getResources()).isEmpty();
    }

    /**
     * Commenting is a mutation (rows, events, notifications), so the derived read-only role must never acquire it even
     * though it is registered for every commentable resource at startup.
     */
    @Test
    void excludesCommentAction() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.DETAIL, ResourceAction.COMMENT));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.CERTIFICATE)).containsExactly(ResourceAction.DETAIL.getCode());
    }

    /**
     * A sensitive read discloses stored secret material or embedded credentials, so it is not part of "may see
     * everything" - a read-only role must not become a way to exfiltrate them.
     */
    @Test
    void excludesSensitiveReadActions() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.SECRET, ResourceAction.DETAIL, ResourceAction.GET_SECRET_CONTENT),
                        resource(Resource.PROXY, ResourceAction.DETAIL, ResourceAction.GET_PROXY_INSTALLATION));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.SECRET)).containsExactly(ResourceAction.DETAIL.getCode());
        assertThat(actionsOf(derived, Resource.PROXY)).containsExactly(ResourceAction.DETAIL.getCode());
    }

    /** Exporting a key hands out its private material, so the read-only role sees the key but never exports it. */
    @Test
    void theReadOnlyRoleNeverHoldsTheExportAction() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, ResourceAction.EXPORT_KEY));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.CRYPTOGRAPHIC_KEY)).containsExactly(ResourceAction.DETAIL.getCode());
    }

    /**
     * The startup scan records {@code ANY} verbatim from the annotations, but the auth service never syncs it into its
     * action catalogue, so emitting it makes it reject the whole permission save with "Unknown action" - the role would
     * then keep whatever it had before, silently.
     */
    @Test
    void excludesTheAnySentinelTheScanRecordsFromAnnotations() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.ANY, ResourceAction.LIST, ResourceAction.DETAIL));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.CERTIFICATE))
                .containsExactlyInAnyOrder(ResourceAction.LIST.getCode(), ResourceAction.DETAIL.getCode());
    }

    @Test
    void grantsNothingBeyondTheActionsItLists() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.CREATE));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(derived.getAllowAllResources()).isFalse();
        assertThat(derived.getResources()).singleElement().satisfies(certificates -> {
            assertThat(certificates.getAllowAllActions()).isFalse();
            assertThat(certificates.getActions()).containsExactly(ResourceAction.LIST.getCode());
            assertThat(certificates.getObjects()).isEmpty();
        });
    }

    /** An empty resource list next to {@code allowAllResources = false} is the deny-everything payload. */
    @Test
    void emptyCatalogueDeniesEverything() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(List.of());

        assertThat(derived.getAllowAllResources()).isFalse();
        assertThat(derived.getResources()).isNotNull().isEmpty();
    }

    /** A resource carrying no action list at all must drop out, for the same reason an all-write one does. */
    @Test
    void treatsAMissingActionListAsNoGrantableActions() {
        ResourceSyncRequestDto withoutActions = new ResourceSyncRequestDto();
        withoutActions.setName(Resource.CERTIFICATE);

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(List.of(withoutActions));

        assertThat(derived.getResources()).isEmpty();
    }

    /**
     * The whole point of deriving rather than listing: a newly added action is classified once, on the enum, and lands
     * on the right side here without anyone editing this role. Runs the entire action catalogue through the derivation,
     * so an action added without a matching access type shows up as a failure.
     */
    @Test
    void grantsExactlyTheReadActionsOfTheWholeActionCatalogue() {
        List<ResourceSyncRequestDto> catalogue = List.of(resource(Resource.CERTIFICATE, ResourceAction.values()));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        List<String> expected = Arrays
                .stream(ResourceAction.values())
                .filter(ResourceAction::isGrantableToReadOnlyRole)
                .map(ResourceAction::getCode)
                .toList();
        assertThat(actionsOf(derived, Resource.CERTIFICATE)).containsExactlyInAnyOrderElementsOf(expected);
    }

    /** The scan collects actions into a set, so only a canonical order makes the emitted payload reproducible. */
    @Test
    void ordersActionsCanonically() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.DETAIL, ResourceAction.EXPORT));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.CERTIFICATE))
                .containsExactly(ResourceAction.DETAIL.getCode(), ResourceAction.EXPORT.getCode(),
                        ResourceAction.LIST.getCode());
    }

    /** A duplicated grant is a duplicated permission row in the auth service, and a spurious "changed" verdict. */
    @Test
    void doesNotRepeatAnActionTheCatalogueListsTwice() {
        List<ResourceSyncRequestDto> catalogue = List
                .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.LIST));

        RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(catalogue);

        assertThat(actionsOf(derived, Resource.CERTIFICATE)).containsExactly(ResourceAction.LIST.getCode());
    }

    // Change detection: the reconciliation replaces the whole permission set, so it only needs to write - and only
    // says so out loud - when what the auth service already holds is not what the catalogue now derives.

    @Test
    void matchesStoredPermissionsThatAlreadyHoldTheDerivedGrants() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List
                        .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.DETAIL,
                                ResourceAction.CREATE)));

        SubjectPermissionsDto stored = stored(false, storedResource(Resource.CERTIFICATE, false,
                List.of(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isTrue();
    }

    /** The auth service returns actions in its own order; a difference in order is not a difference in grants. */
    @Test
    void matchesStoredPermissionsListedInADifferentOrder() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.DETAIL)));

        SubjectPermissionsDto stored = stored(false, storedResource(Resource.CERTIFICATE, false,
                List.of(ResourceAction.LIST.getCode(), ResourceAction.DETAIL.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isTrue();
    }

    @Test
    void differsWhenStoredHoldsAnActionTheCatalogueNoLongerGrants() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        SubjectPermissionsDto stored = stored(false, storedResource(Resource.CERTIFICATE, false,
                List.of(ResourceAction.LIST.getCode(), ResourceAction.REVOKE.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    @Test
    void differsWhenStoredIsMissingAResourceTheCatalogueNowGrants() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List
                        .of(resource(Resource.CERTIFICATE, ResourceAction.LIST),
                                resource(Resource.SECRET, ResourceAction.LIST)));

        SubjectPermissionsDto stored = stored(false,
                storedResource(Resource.CERTIFICATE, false, List.of(ResourceAction.LIST.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    @Test
    void differsWhenStoredHoldsAResourceTheCatalogueNoLongerGrants() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        SubjectPermissionsDto stored = stored(false,
                storedResource(Resource.CERTIFICATE, false, List.of(ResourceAction.LIST.getCode())),
                storedResource(Resource.SECRET, false, List.of(ResourceAction.LIST.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    /** The auth service can report a role with no grants as an absent list rather than an empty one. */
    @Test
    void differsWhenStoredHasNoResourceListAtAll() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        SubjectPermissionsDto stored = new SubjectPermissionsDto();
        stored.setAllowAllResources(false);

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    @Test
    void differsWhenStoredAllowsAllActionsOnAResource() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        SubjectPermissionsDto stored = stored(false, storedResource(Resource.CERTIFICATE, true, List.of()));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    @Test
    void differsWhenStoredAllowsAllResources() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        SubjectPermissionsDto stored = stored(true,
                storedResource(Resource.CERTIFICATE, false, List.of(ResourceAction.LIST.getCode())));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored)).isFalse();
    }

    /**
     * Object-level entries are grants too, and the derivation emits none - so a role carrying one is out of step and
     * must be rewritten, otherwise a hand-added object grant would survive every reconciliation untouched.
     */
    @Test
    void differsWhenStoredCarriesObjectLevelGrants() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        ResourcePermissionsDto withObject = storedResource(Resource.CERTIFICATE, false,
                List.of(ResourceAction.LIST.getCode()));
        ObjectPermissionsDto object = new ObjectPermissionsDto();
        object.setUuid("6dcd2c62-2b4f-4d2b-9e2a-6b7b0c3a1f45");
        object.setAllow(List.of(ResourceAction.MEMBERS.getCode()));
        withObject.setObjects(List.of(object));

        assertThat(ReadOnlyRolePermissions.matches(derived, stored(false, withObject))).isFalse();
    }

    /** No answer from the auth service is not evidence the role is already in step. */
    @Test
    void differsWhenStoredPermissionsAreAbsent() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List.of(resource(Resource.CERTIFICATE, ResourceAction.LIST)));

        assertThat(ReadOnlyRolePermissions.matches(derived, null)).isFalse();
    }

    @Test
    void countsTheGrantedActionsAcrossAllResources() {
        RolePermissionsRequestDto derived = ReadOnlyRolePermissions
                .deriveFrom(List
                        .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.DETAIL,
                                ResourceAction.CREATE), resource(Resource.SECRET, ResourceAction.LIST)));

        assertThat(ReadOnlyRolePermissions.countActions(derived)).isEqualTo(3);
    }

    private static SubjectPermissionsDto stored(boolean allowAllResources, ResourcePermissionsDto... resources) {
        SubjectPermissionsDto dto = new SubjectPermissionsDto();
        dto.setAllowAllResources(allowAllResources);
        dto.setResources(List.of(resources));
        return dto;
    }

    private static ResourcePermissionsDto storedResource(Resource resource, boolean allowAllActions,
            List<String> actions) {
        ResourcePermissionsDto dto = new ResourcePermissionsDto();
        dto.setName(resource.getCode());
        dto.setAllowAllActions(allowAllActions);
        dto.setActions(actions);
        dto.setObjects(List.of());
        return dto;
    }

    private static List<String> actionsOf(RolePermissionsRequestDto derived, Resource resource) {
        return derived
                .getResources()
                .stream()
                .filter(r -> resource.getCode().equals(r.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(resource.getCode() + " missing from derived payload"))
                .getActions();
    }

    private static ResourceSyncRequestDto resource(Resource resource, ResourceAction... actions) {
        ResourceSyncRequestDto dto = new ResourceSyncRequestDto();
        dto.setName(resource);
        dto.setActions(Arrays.stream(actions).map(ResourceAction::getCode).toList());
        return dto;
    }
}
