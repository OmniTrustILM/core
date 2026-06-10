package db.migration;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.util.DatabaseAttributeMigration;
import com.otilm.core.util.DatabaseMigration;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;

/**
 * Migration script for the Json array migration to separate table
 */
public class V202402171510__UpdateAndOptimizeAttributesModelMigration extends BaseJavaMigration {
    private static final Logger logger = LoggerFactory.getLogger(V202402171510__UpdateAndOptimizeAttributesModelMigration.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202402171510__UpdateAndOptimizeAttributesModelMigration.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        updateNullAttributeUuids(context);
        prepareDBStructure(context);
        Map<UUID, List<UUID>> mappedContentToItems = deduplicateContentItems(context);
        assignAttributeContentItemsToResourceObjects(context, mappedContentToItems);
        cleanDbStructure(context);
        moveDataAttributes(context);
    }

    private void updateNullAttributeUuids(Context context) throws SQLException {
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute("UPDATE attribute_definition SET attribute_uuid = uuid WHERE attribute_uuid IS NULL");
        }
    }

    private void prepareDBStructure(Context context) throws SQLException {
        String sqlCommands = """
                ALTER TABLE attribute_definition
                    ADD COLUMN operation TEXT NULL,
                    ADD COLUMN name TEXT NULL,
                    ADD COLUMN type TEXT NULL,
                    ADD COLUMN content_type TEXT NULL,
                    ADD COLUMN label TEXT NULL,
                    ADD COLUMN required BOOLEAN NULL,
                    ADD COLUMN read_only BOOLEAN NULL,
                    ADD COLUMN definition JSONB NULL,
                    ADD COLUMN created_at TIMESTAMP NULL,
                    ADD COLUMN updated_at TIMESTAMP NULL,
                    DROP COLUMN i_author,
                    DROP COLUMN reference;
                
                ALTER TABLE attribute_definition DROP CONSTRAINT attribute_definition_to_connector_key;
                ALTER TABLE attribute_definition ADD CONSTRAINT fk_attribute_definition_connector FOREIGN KEY (connector_uuid) REFERENCES connector(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                                        
                ALTER TABLE attribute_content_item
                    ADD COLUMN attribute_definition_uuid UUID NULL;
                                        
                ALTER TABLE attribute_content_2_object
                    ADD COLUMN item_order SMALLINT DEFAULT 0 NOT NULL,
                    ADD COLUMN attribute_content_item_uuid UUID NULL;
                                        
                ALTER TABLE attribute_content_item ADD CONSTRAINT fk_attribute_content_item_attribute_definition FOREIGN KEY (attribute_definition_uuid) REFERENCES attribute_definition(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                ALTER TABLE attribute_content_2_object DROP CONSTRAINT attribute_definition_to_connector_key;
                ALTER TABLE attribute_content_2_object ADD CONSTRAINT fk_attribute_content_2_object_connector FOREIGN KEY (connector_uuid) REFERENCES connector(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                ALTER TABLE attribute_content_2_object ADD CONSTRAINT fk_attribute_content_2_object_attribute_content_item FOREIGN KEY (attribute_content_item_uuid) REFERENCES attribute_content_item(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                                        
                -- update new columns
                UPDATE attribute_definition SET name = attribute_name, type = attribute_type, content_type = attribute_content_type, definition = attribute_definition::jsonb, created_at = i_cre, updated_at = i_upd;
                UPDATE attribute_definition SET label = definition->'properties'->>'label';
                UPDATE attribute_definition SET required = (definition->'properties'->>'required')::bool, read_only = (definition->'properties'->>'readOnly')::bool WHERE attribute_type = 'CUSTOM' OR attribute_type = 'DATA';
                                        
                UPDATE attribute_content_item SET attribute_definition_uuid = (SELECT ac.attribute_definition_uuid FROM attribute_content AS ac WHERE ac.uuid = attribute_content_item.attribute_content_uuid);
                DELETE FROM attribute_content_item WHERE attribute_definition_uuid IS NULL;
                                        
                -- drop original column and set correct constraints
                ALTER TABLE attribute_definition
                    ALTER COLUMN attribute_uuid SET NOT NULL,
                    ALTER COLUMN name SET NOT NULL,
                    ALTER COLUMN type SET NOT NULL,
                    ALTER COLUMN content_type SET NOT NULL,
                    ALTER COLUMN label SET NOT NULL,
                    ALTER COLUMN definition SET NOT NULL,
                    ALTER COLUMN created_at SET NOT NULL,
                    ALTER COLUMN updated_at SET NOT NULL,
                    DROP COLUMN i_cre,
                    DROP COLUMN i_upd,
                    DROP COLUMN attribute_definition,
                    DROP COLUMN attribute_name,
                    DROP COLUMN attribute_type,
                    DROP COLUMN attribute_content_type;
                                        
                ALTER TABLE attribute_content_item
                    ALTER COLUMN json SET NOT NULL,
                    ALTER COLUMN attribute_definition_uuid SET NOT NULL;
                    
                ALTER TABLE attribute_relation
                    ALTER COLUMN attribute_definition_uuid SET NOT NULL
                """;
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute(sqlCommands);
        }
    }

    private Map<UUID, List<UUID>> deduplicateContentItems(Context context) throws SQLException {
        Map<UUID, List<UUID>> mappedContentToItems = new HashMap<>();
        try (final Statement statement = context.getConnection().createStatement(); final PreparedStatement deleteStatement = context.getConnection().prepareStatement("DELETE FROM attribute_content_item WHERE uuid = ?");) {
            int deletesCount = 0;
            try (ResultSet rows = statement.executeQuery("SELECT * FROM attribute_content_item aci ORDER BY aci.attribute_definition_uuid, aci.attribute_content_uuid")) {
                UUID contentUuid = null;
                UUID definitionUuid = null;
                List<UUID> contentItems = null;
                Map<String, UUID> mappingJsonToItem = null;
                while (rows.next()) {
                    final UUID contentItemUuid = rows.getObject("uuid", UUID.class);
                    final UUID currentDefinitionUuid = rows.getObject("attribute_definition_uuid", UUID.class);

                    final String json = rows.getString("json");
                    final UUID currentContentUuid = rows.getObject("attribute_content_uuid", UUID.class);

                    if (!currentDefinitionUuid.equals(definitionUuid)) {
                        mappingJsonToItem = new HashMap<>();
                        definitionUuid = currentDefinitionUuid;
                    }
                    if (!currentContentUuid.equals(contentUuid)) {
                        contentItems = new ArrayList<>();
                        contentUuid = currentContentUuid;
                        mappedContentToItems.put(contentUuid, contentItems);
                    }

                    // handle content item
                    UUID mappedContentItemUuid = mappingJsonToItem.get(json);
                    if (mappedContentItemUuid == null) {
                        mappedContentItemUuid = contentItemUuid;
                        mappingJsonToItem.put(json, contentItemUuid);
                    } else {
                        // duplicate content item
                        ++deletesCount;
                        deleteStatement.setObject(1, contentItemUuid);
                        deleteStatement.addBatch();
                    }
                    contentItems.add(mappedContentItemUuid);
                }
            }

            logger.debug("Removing {} duplicate attribute content items.", deletesCount);
            deleteStatement.executeBatch();
        }

        return mappedContentToItems;
    }

    private void assignAttributeContentItemsToResourceObjects(Context context, Map<UUID, List<UUID>> mappedContentToItems) throws SQLException {
        try (final Statement statement = context.getConnection().createStatement();
             final PreparedStatement insertStatement = context.getConnection().prepareStatement("INSERT INTO attribute_content_2_object(uuid, connector_uuid, attribute_content_uuid, attribute_content_item_uuid, object_type, object_uuid, source_object_type, source_object_uuid, source_object_name, item_order) VALUES (?,?,?,?,?,?,?,?,?,?)");
             final PreparedStatement updateStatement = context.getConnection().prepareStatement("UPDATE attribute_content_2_object SET attribute_content_item_uuid = ? WHERE uuid = ?")) {
            int insertsCount = 0;
            int updatesCount = 0;
            try (ResultSet rows = statement.executeQuery("SELECT * FROM attribute_content_2_object ac2o ORDER BY ac2o.attribute_content_uuid")) {
                List<UUID> contentItems;
                while (rows.next()) {
                    final UUID uuid = rows.getObject("uuid", UUID.class);
                    final UUID contentUuid = rows.getObject("attribute_content_uuid", UUID.class);
                    contentItems = mappedContentToItems.get(contentUuid);
                    if (contentItems == null || contentItems.isEmpty()) {
                        continue;
                    }

                    // update object content to refer first item
                    ++updatesCount;
                    UUID contentItemUuid = contentItems.get(0);
                    updateStatement.setObject(1, contentItemUuid);
                    updateStatement.setObject(2, uuid);
                    updateStatement.addBatch();

                    // if more content items, duplicate content assignment to objects
                    for (int i = 1; i < contentItems.size(); i++) {
                        ++insertsCount;

                        UUID connectorUuid = rows.getObject("connector_uuid", UUID.class);
                        UUID sourceObjectUuid = rows.getObject("source_object_uuid", UUID.class);
                        insertStatement.setObject(1, UUID.randomUUID());
                        insertStatement.setObject(2, connectorUuid);
                        insertStatement.setObject(3, contentUuid);
                        insertStatement.setObject(4, contentItems.get(i));
                        insertStatement.setString(5, rows.getString("object_type"));
                        insertStatement.setObject(6, rows.getObject("object_uuid", UUID.class));
                        insertStatement.setString(7, rows.getString("source_object_type"));
                        insertStatement.setObject(8, sourceObjectUuid);
                        insertStatement.setString(9, rows.getString("source_object_name"));
                        insertStatement.setInt(10, i);
                        insertStatement.addBatch();
                    }
                }
            }

            logger.debug("Executing batch update with {} resource objects attribute content item assignment.", updatesCount);
            updateStatement.executeBatch();

            logger.debug("Executing batch insert with {} resource objects attribute content item assignment.", insertsCount);
            insertStatement.executeBatch();

            logger.debug("Removing orphaned resource objects attribute contents.");
            int deleted = statement.executeUpdate("DELETE FROM attribute_content_2_object WHERE attribute_content_item_uuid IS NULL");
            logger.debug("Removed {} orphaned resource objects attribute contents.", deleted);
        }
    }

    private void moveDataAttributes(Context context) throws SQLException, JsonProcessingException {
        // preload existing data attributes definitions that were used until now as reference for group attributes content validation
        DatabaseAttributeMigration.loadExistingDataAttributesDefinitions(context);

        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.ACME_PROFILE, "acme_profile", new String[]{"issue_certificate_attributes", "revoke_certificate_attributes"}, new String[]{AttributeOperation.CERTIFICATE_ISSUE, AttributeOperation.CERTIFICATE_REVOKE}, new boolean[]{true, true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.SCEP_PROFILE, "scep_profile", new String[]{"issue_certificate_attributes", "revoke_certificate_attributes"}, new String[]{AttributeOperation.CERTIFICATE_ISSUE, AttributeOperation.CERTIFICATE_REVOKE}, new boolean[]{true, true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.CERTIFICATE, "certificate", new String[]{"issue_attributes", "revoke_attributes"}, new String[]{AttributeOperation.CERTIFICATE_ISSUE, AttributeOperation.CERTIFICATE_REVOKE}, new boolean[]{true, true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.CERTIFICATE_REQUEST, "certificate_request", new String[]{"attributes", "signature_attributes"}, new String[]{null, AttributeOperation.CERTIFICATE_REQUEST_SIGN}, new boolean[]{false, false});
//        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.CONNECTOR, "connector", new String[]{"auth_attributes"}, new String[]{AttributeOperation.CONNECTOR_AUTH}, new boolean[]{false});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.CREDENTIAL, "credential", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.CRYPTOGRAPHIC_KEY, "cryptographic_key", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.DISCOVERY, "discovery_history", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.LOCATION, "location", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.RA_PROFILE, "ra_profile", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.TOKEN, "token_instance_reference", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
        DatabaseAttributeMigration.moveTableDataAttributes(context, Resource.TOKEN_PROFILE, "token_profile", new String[]{"attributes"}, new String[]{null}, new boolean[]{true});
    }

    private void cleanDbStructure(Context context) throws Exception {
        try (Statement statement = context.getConnection().createStatement()) {
            statement.addBatch("ALTER TABLE attribute_content_2_object DROP COLUMN attribute_content_uuid, ALTER COLUMN attribute_content_item_uuid SET NOT NULL");
            statement.addBatch("ALTER TABLE attribute_content_item DROP COLUMN attribute_content_uuid");
            statement.addBatch("DROP TABLE attribute_content");

            statement.executeBatch();
        }
    }
}
