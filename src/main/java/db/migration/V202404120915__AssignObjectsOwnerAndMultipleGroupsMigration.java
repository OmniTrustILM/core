package db.migration;

import com.otilm.api.model.core.auth.*;
import com.otilm.core.model.auth.ResourceAction;
import com.czertainly.core.model.auth.ResourceSyncRequestDto;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.DatabaseAuthMigration;
import com.czertainly.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.io.IOException;
import java.net.URISyntaxException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

public class V202404120915__AssignObjectsOwnerAndMultipleGroupsMigration extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202404120915__AssignObjectsOwnerAndMultipleGroupsMigration.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        createDBTable(context);
        migrateGroupsAndOwners(context, "certificate", Resource.CERTIFICATE);
        migrateGroupsAndOwners(context, "cryptographic_key", Resource.CRYPTOGRAPHIC_KEY);
        seedMembersAction();
        updateProtocolRolesPermissions();
        cleanDbStructure(context);
    }

    private void createDBTable(Context context) throws SQLException {
        String sqlCommands = """
                CREATE TABLE "group_association"
                (
                    "uuid"                          UUID      NOT NULL,
                    "resource"                      TEXT      NOT NULL,
                    "object_uuid"                   UUID      NOT NULL,
                    "group_uuid"                    UUID      NOT NULL,
                    PRIMARY KEY ("uuid"),
                    FOREIGN KEY ("group_uuid") REFERENCES "group" ("uuid")
                );
                                
                CREATE TABLE "owner_association"
                (
                    "uuid"                          UUID      NOT NULL,
                    "resource"                      TEXT      NOT NULL,
                    "object_uuid"                   UUID      NOT NULL,
                    "owner_uuid"                    UUID      NOT NULL,
                    "owner_username"                TEXT      NOT NULL,
                    PRIMARY KEY ("uuid")
                );
                                
                ALTER TABLE cryptographic_key_item
                    ADD COLUMN created_at TIMESTAMP NULL,
                    ADD COLUMN updated_at TIMESTAMP NULL;
                    
                UPDATE cryptographic_key_item SET created_at = (SELECT k.i_cre FROM cryptographic_key AS k WHERE k.uuid = cryptographic_key_item.cryptographic_key_uuid);
                UPDATE cryptographic_key_item SET updated_at = created_at;
                                
                ALTER TABLE cryptographic_key_item
                    ALTER COLUMN created_at SET NOT NULL,
                    ALTER COLUMN updated_at SET NOT NULL;
                """;

        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute(sqlCommands);
        }
    }

    private void migrateGroupsAndOwners(Context context, String tableName, Resource resource) throws SQLException {
        try (final Statement selectStatement = context.getConnection().createStatement();
             final PreparedStatement insertGroupStatement = context.getConnection().prepareStatement("INSERT INTO group_association(uuid, resource, object_uuid, group_uuid) VALUES (?,?,?,?)");
             final PreparedStatement insertOwnerStatement = context.getConnection().prepareStatement("INSERT INTO owner_association(uuid, resource, object_uuid, owner_uuid, owner_username) VALUES (?,?,?,?,?)")) {

            ResultSet rows = selectStatement.executeQuery(String.format("SELECT uuid, group_uuid, owner, owner_uuid FROM %s WHERE group_uuid IS NOT NULL OR owner_uuid IS NOT NULL", tableName));
            while (rows.next()) {
                UUID objectUuid = rows.getObject("uuid", UUID.class);
                UUID groupUuid = rows.getObject("group_uuid", UUID.class);
                UUID ownerUuid = rows.getObject("owner_uuid", UUID.class);

                if (groupUuid != null) {
                    insertGroupStatement.setObject(1, UUID.randomUUID());
                    insertGroupStatement.setString(2, resource.toString());
                    insertGroupStatement.setObject(3, objectUuid);
                    insertGroupStatement.setObject(4, groupUuid);
                    insertGroupStatement.addBatch();
                }
                if (ownerUuid != null) {
                    insertOwnerStatement.setObject(1, UUID.randomUUID());
                    insertOwnerStatement.setString(2, resource.toString());
                    insertOwnerStatement.setObject(3, objectUuid);
                    insertOwnerStatement.setObject(4, ownerUuid);
                    insertOwnerStatement.setString(5, rows.getString("owner"));
                    insertOwnerStatement.addBatch();
                }
            }

            insertGroupStatement.executeBatch();
            insertOwnerStatement.executeBatch();
        }
    }

    private void seedMembersAction() throws IOException, URISyntaxException {
        List<ResourceSyncRequestDto> resourceRequests = new ArrayList<>();
        List<com.czertainly.core.model.auth.Resource> resources = List.of(com.czertainly.core.model.auth.Resource.ATTRIBUTE, com.czertainly.core.model.auth.Resource.AUTHORITY, com.czertainly.core.model.auth.Resource.RA_PROFILE);

        for (var resource : resources) {
            ResourceSyncRequestDto requestDto = new ResourceSyncRequestDto();
            requestDto.setName(resource);
            requestDto.setActions(List.of(ResourceAction.MEMBERS.getCode()));
            resourceRequests.add(requestDto);
        }

        DatabaseAuthMigration.getResourceApiClient().addResources(resourceRequests);
    }

    private void updateProtocolRolesPermissions() throws IOException, URISyntaxException {
        Map<String, String> rolesMapping = DatabaseAuthMigration.getSystemRolesMapping();

        Map<Resource, List<ResourceAction>> resourceActions = new HashMap<>();
        resourceActions.put(Resource.ATTRIBUTE, List.of(ResourceAction.MEMBERS));
        resourceActions.put(Resource.AUTHORITY, List.of(ResourceAction.MEMBERS));
        resourceActions.put(Resource.RA_PROFILE, List.of(ResourceAction.MEMBERS));

        DatabaseAuthMigration.updateRolePermissions(rolesMapping.get(AuthHelper.ACME_USERNAME), resourceActions);
        DatabaseAuthMigration.updateRolePermissions(rolesMapping.get(AuthHelper.SCEP_USERNAME), resourceActions);
    }

    private void cleanDbStructure(Context context) throws SQLException {
        String sqlCommands = """
                ALTER TABLE certificate
                      DROP COLUMN owner,
                      DROP COLUMN owner_uuid,
                      DROP COLUMN group_uuid;
                ALTER TABLE cryptographic_key
                      DROP COLUMN owner,
                      DROP COLUMN owner_uuid,
                      DROP COLUMN group_uuid;
                """;

        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute(sqlCommands);
        }
    }
}
