package db.migration;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DatabaseAuthMigration;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Grants {@code RA_PROFILE:MEMBERS}, {@code GROUP:MEMBERS}, and {@code ATTRIBUTE:MEMBERS} to the
 * {@code attribute-content-resolver} role, so a CERTIFICATE dereference running as this identity is not denied a
 * transitive 403. Each grant is motivated separately.
 * <p>
 * <b>{@code RA_PROFILE:MEMBERS} (primary fix):</b> a CERTIFICATE dereference passes through
 * {@code RaProfileInternalService.evaluateCertificateRaProfilePermissions}, whose authorization names it as the
 * parent gate — the certificate counterpart of the SECRET path's {@code VAULT_PROFILE:MEMBERS}.
 * <p>
 * <b>{@code GROUP:MEMBERS} (fail-safe):</b> covers the group-membership fallback the authorization core evaluates
 * when a direct decision denies, so a policy-shape change cannot reintroduce a transitive 403 for group-assigned
 * certificates. The fallback is not certificate-scoped: if reachable for this role it authorizes group-based
 * DETAIL/LIST on any group-eligible resource — deliberate breadth, matching the seed migration.
 * <p>
 * <b>{@code ATTRIBUTE:MEMBERS} (fail-safe):</b> guards the custom-attribute content filter
 * ({@code AttributeEngine#loadCustomAttributesSecurityResourceFilter}), which without a role-level grant is an
 * empty allowlist that silently drops content instead of returning a 403 — the harder-to-diagnose gap should the
 * dereference path ever load custom attributes.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202608311000__GrantRaProfileMembersToAttributeContentResolver extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202608311000__GrantRaProfileMembersToAttributeContentResolver
                .getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        Map<Resource, List<ResourceAction>> addedResourceActions = new EnumMap<>(Resource.class);
        addedResourceActions.put(Resource.RA_PROFILE, List.of(ResourceAction.MEMBERS));
        addedResourceActions.put(Resource.GROUP, List.of(ResourceAction.MEMBERS));
        addedResourceActions.put(Resource.ATTRIBUTE, List.of(ResourceAction.MEMBERS));

        // On a fresh install this migration runs before Core's catalog sync, and the auth service rejects
        // permissions naming an unknown resource/action. Additive no-op where the pair is already known.
        DatabaseAuthMigration.seedResources(addedResourceActions);

        String roleUuid = DatabaseAuthMigration
                .getSystemRolesMapping()
                .get(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME);
        if (roleUuid == null) {
            throw new IllegalStateException(
                    "System role '%s' not found; V202607031200 must have created it before this migration runs"
                            .formatted(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME));
        }

        DatabaseAuthMigration.updateRolePermissions(roleUuid, addedResourceActions);
    }
}
