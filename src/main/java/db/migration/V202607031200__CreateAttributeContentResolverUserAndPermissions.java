package db.migration;

import com.otilm.api.model.core.auth.*;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DatabaseAuthMigration;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Seeds the {@code attribute-content-resolver} system user + role. The platform assumes this identity (via
 * {@code AuthHelper.runAsSystem}, from {@code OperationAttributeResolver}) to resolve an authority's own
 * infrastructure references into inline content when assembling an operation-path connector request, so a stateless
 * connector receives usable content without gating on the acting caller (operator, protocol robot, or the
 * principal-less status-poll thread).
 * <p>
 * The role covers every referenceable {@code AttributeResource} kind — including AUTHORITY/ENTITY/LOCATION, which
 * currently resolve through an unguarded engine read — so that when those reads are eventually guarded the resolver
 * fails safe (it already holds the grant) rather than starting to deny. Beyond those kinds, {@code CONNECTOR:DETAIL}
 * and {@code VAULT_PROFILE:MEMBERS} are needed transitively by a SECRET dereference — it loads the secret's vault
 * connector and checks vault-profile membership. The granted pairs are seeded into the auth service before the role is
 * created: Core's catalog sync runs only after Flyway, so on a fresh install the auth service would otherwise reject
 * the role for a not-yet-known resource/action.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202607031200__CreateAttributeContentResolverUserAndPermissions extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202607031200__CreateAttributeContentResolverUserAndPermissions.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        Map<Resource, List<ResourceAction>> roleResourceActions = new EnumMap<>(Resource.class);
        roleResourceActions.put(Resource.CONNECTOR, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.CREDENTIAL, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.CERTIFICATE, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.AUTHORITY, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.ENTITY, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.LOCATION, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.VAULT_PROFILE, List.of(ResourceAction.MEMBERS));
        roleResourceActions.put(Resource.SECRET, List.of(ResourceAction.DETAIL, ResourceAction.GET_SECRET_CONTENT));

        // Seed the granted pairs into the auth service before creating the role: the auth service rejects a role
        // referencing an unknown resource/action, and Core's catalog sync runs only after Flyway. addResources is
        // additive, so re-seeding long-standing pairs is a safe no-op.
        DatabaseAuthMigration.seedResources(roleResourceActions);

        RoleRequestDto roleRequestDto = new RoleRequestDto();
        roleRequestDto.setName(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME);
        roleRequestDto.setDescription("System role for resolving an authority's own infrastructure references (any referenceable resource kind) into inline content when assembling operation-path connector requests");
        roleRequestDto.setSystemRole(true);
        RoleDetailDto role = DatabaseAuthMigration.createRole(roleRequestDto, roleResourceActions);

        UserRequestDto userRequestDto = new UserRequestDto();
        userRequestDto.setUsername(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME);
        userRequestDto.setDescription("System user the platform assumes to dereference an authority's own infrastructure references on the operation path");
        userRequestDto.setEnabled(true);
        userRequestDto.setSystemUser(true);

        List<String> roleUuids = new ArrayList<>();
        roleUuids.add(role.getUuid());
        DatabaseAuthMigration.createUser(userRequestDto, roleUuids);
    }
}
