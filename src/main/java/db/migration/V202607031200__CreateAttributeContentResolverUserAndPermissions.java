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
 * Seeds the least-privilege {@code attribute-content-resolver} system user + role. The platform assumes this identity
 * (via {@code AuthHelper.runAsSystem}, from {@code OperationAttributeResolver}) to resolve an authority's own
 * infrastructure references — connector, credential, certificate, and secret content + vault-profile membership — when assembling an
 * operation-path connector request, so a stateless connector receives inline content without gating on the acting
 * caller (operator, protocol robot, or the principal-less status-poll thread). Grants are exactly the read actions
 * the guarded resolution mechanics touch; object-config kinds (AUTHORITY/ENTITY/LOCATION) resolve via an unguarded
 * engine read and need no grant here.
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
        // create role
        Map<Resource, List<ResourceAction>> roleResourceActions = new EnumMap<>(Resource.class);
        roleResourceActions.put(Resource.CONNECTOR, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.CREDENTIAL, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.SECRET, List.of(ResourceAction.GET_SECRET_CONTENT));
        roleResourceActions.put(Resource.VAULT_PROFILE, List.of(ResourceAction.MEMBERS));
        roleResourceActions.put(Resource.CERTIFICATE, List.of(ResourceAction.DETAIL));

        RoleRequestDto roleRequestDto = new RoleRequestDto();
        roleRequestDto.setName(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME);
        roleRequestDto.setDescription("System role for resolving an authority's own infrastructure references (connector, credential, secret) when assembling operation-path connector requests");
        roleRequestDto.setSystemRole(true);
        RoleDetailDto role = DatabaseAuthMigration.createRole(roleRequestDto, roleResourceActions);

        // create user
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
