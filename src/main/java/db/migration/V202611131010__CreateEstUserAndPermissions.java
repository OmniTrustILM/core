package db.migration;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.RoleRequestDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DatabaseAuthMigration;
import com.otilm.core.util.DatabaseMigration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/**
 * Seeds the {@code est} system user + role: the identity the protocol filter authenticates EST requests as.
 * <p>
 * <b>Least privilege:</b> the role reads the EST Profile, RA Profile and Authority a request routes to, and enrols
 * certificates against them. {@code CERTIFICATE:REKEY} lets a re-enrolment replace the key, and there is no
 * {@code CERTIFICATE:REVOKE} because EST has no revocation operation. For server-side key generation with key recovery
 * it creates the key on the token profile, exports it once for the answer, and destroys it when no certificate keeps
 * it: {@code CRYPTOGRAPHIC_KEY} CREATE, DETAIL, EXPORT_KEY and DELETE, {@code TOKEN_PROFILE} DETAIL, and {@code TOKEN}
 * DETAIL and MEMBERS. It holds nothing else.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202611131010__CreateEstUserAndPermissions extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202611131010__CreateEstUserAndPermissions.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        List<ResourceAction> readActions = List.of(ResourceAction.DETAIL, ResourceAction.LIST, ResourceAction.MEMBERS);
        List<ResourceAction> certificateActions = List
                .of(ResourceAction.CREATE, ResourceAction.ISSUE, ResourceAction.DETAIL, ResourceAction.UPDATE,
                        ResourceAction.RENEW, ResourceAction.REKEY, ResourceAction.LIST);

        Map<Resource, List<ResourceAction>> roleResourceActions = new EnumMap<>(Resource.class);
        roleResourceActions.put(Resource.EST_PROFILE, readActions);
        roleResourceActions.put(Resource.RA_PROFILE, readActions);
        roleResourceActions.put(Resource.AUTHORITY, readActions);
        roleResourceActions.put(Resource.CERTIFICATE, certificateActions);
        roleResourceActions
                .put(Resource.CRYPTOGRAPHIC_KEY, List
                        .of(ResourceAction.CREATE, ResourceAction.DETAIL, ResourceAction.EXPORT_KEY,
                                ResourceAction.DELETE));
        roleResourceActions.put(Resource.TOKEN_PROFILE, List.of(ResourceAction.DETAIL));
        roleResourceActions.put(Resource.TOKEN, List.of(ResourceAction.DETAIL, ResourceAction.MEMBERS));

        // Seed first: the auth service rejects a role that names a resource or action it does not know. EST_PROFILE
        // is new to the auth service, and Core's catalog sync, which would register it, runs only after Flyway.
        DatabaseAuthMigration.seedResources(roleResourceActions);

        RoleRequestDto roleRequestDto = new RoleRequestDto();
        roleRequestDto.setName(AuthHelper.EST_USERNAME);
        roleRequestDto.setDescription("System role with the permissions needed for EST operations");
        roleRequestDto.setSystemRole(true);
        RoleDetailDto role = DatabaseAuthMigration.createRole(roleRequestDto, roleResourceActions);

        UserRequestDto userRequestDto = new UserRequestDto();
        userRequestDto.setUsername(AuthHelper.EST_USERNAME);
        userRequestDto.setDescription("System user for EST operations");
        userRequestDto.setEnabled(true);
        userRequestDto.setSystemUser(true);

        // The auth client serializes the role list as an ArrayList, which an immutable List.of(...) is not.
        List<String> roleUuids = new ArrayList<>();
        roleUuids.add(role.getUuid());
        DatabaseAuthMigration.createUser(userRequestDto, roleUuids);
    }
}
