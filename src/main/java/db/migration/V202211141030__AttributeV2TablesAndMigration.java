package db.migration;

import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.DatabaseMigration;
import com.otilm.core.util.V2AttributeMigrationUtils;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Migration script for the Metadata changes.
 * Prerequisite for the successful migration is to have the AttributeDefinition stored in the database.
 * If the relaxed version of the AttributeDefinition is stored, the migration will fail, including missing
 * type, name, uuid, label.
 */
public class V202211141030__AttributeV2TablesAndMigration extends BaseJavaMigration {

    private static final String META_COLUMN_NAME = "meta";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202211141030__AttributeV2TablesAndMigration.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            createTables(context);
            List<String> availableConnectors = getAvailableConnectors(context);
            List<String> discoveryMigrationCommands = migrateDiscoveryTable(context, availableConnectors);
            executeCommands(select, discoveryMigrationCommands);
            List<String> certificateMigrationCommands = migrateCertificateTable(context);
            executeCommands(select, certificateMigrationCommands);
            List<String> locationMigrationCommands = migrateLocationTable(context, availableConnectors);
            executeCommands(select, locationMigrationCommands);
            List<String> certificateLocationMigrationCommands = migrateCertificateLocationTable(context, availableConnectors);
            executeCommands(select, certificateLocationMigrationCommands);
            cleanTables(context);
        }
    }

    private List<String> migrateDiscoveryTable(Context context, List<String> availableConnectors) throws Exception {
        List<String> migrationCommands = new ArrayList<>();
        Map<String, String> definitionUuid = new HashMap<>();
        Map<String, String> contentUuids = new HashMap<>();
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT * FROM discovery_history ORDER BY uuid")) {
                while (rows.next()) {
                    List<MetadataAttributeV2> attributes = V2AttributeMigrationUtils.getMetadataMigrationAttributes(rows.getString(META_COLUMN_NAME));
                    if (attributes == null) {
                        continue;
                    }
                    for (MetadataAttributeV2 metadata : attributes) {
                        String attributeDefinition = AttributeDefinitionUtils.serialize(metadata);
                        String attributeContent = AttributeDefinitionUtils.serializeAttributeContent(metadata.getContent());
                        String uuid;
                        String connectorUuid = availableConnectors.contains(rows.getString("connector_uuid")) ? rows.getString("connector_uuid") : null;
                        if (definitionUuid.containsKey(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName())) {
                            uuid = definitionUuid.get(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName());
                        } else {
                            uuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeDefinitionCommandGenerator(attributeDefinition, uuid, connectorUuid, metadata.getName(), metadata.getType().toString(), metadata.getContentType().toString()));
                            definitionUuid.put(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName(), uuid);
                        }
                        String contentUuid;
                        if (contentUuids.containsKey(attributeContent + uuid)) {
                            contentUuid = contentUuids.get(attributeContent + uuid);
                        } else {
                            contentUuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeContentCommandGenerator(attributeContent, contentUuid, uuid));
                            contentUuids.put(attributeContent + uuid, contentUuid);
                        }
                        migrationCommands.add(attributeContent2ObjectCommandGenerator(UUID.randomUUID().toString(),
                                contentUuid,
                                "DISCOVERY",
                                rows.getString("uuid"),
                                null,
                                null,
                                null,
                                connectorUuid)
                        );
                    }
                }
            }
        }
        return migrationCommands;
    }

    private List<String> migrateCertificateTable(Context context) throws Exception {
        List<String> migrationCommands = new ArrayList<>();
        Map<String, String> definitionUuid = new HashMap<>();
        Map<String, String> contentUuids = new HashMap<>();
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT uuid, meta FROM certificate ORDER BY uuid")) {
                while (rows.next()) {
                    List<MetadataAttributeV2> attributes = V2AttributeMigrationUtils.getMetadataMigrationAttributes(rows.getString(META_COLUMN_NAME));
                    if (attributes == null) {
                        continue;
                    }
                    for (MetadataAttributeV2 metadata : attributes) {
                        String attributeDefinition = AttributeDefinitionUtils.serialize(metadata);
                        String attributeContent = AttributeDefinitionUtils.serializeAttributeContent(metadata.getContent());
                        String uuid;
                        if (definitionUuid.containsKey(metadata.getName())) {
                            uuid = definitionUuid.get(metadata.getName());
                        } else {
                            uuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeDefinitionCommandGenerator(attributeDefinition, uuid, null, metadata.getName(), metadata.getType().toString(), metadata.getContentType().toString()));
                            definitionUuid.put(metadata.getName(), uuid);
                        }
                        String contentUuid;
                        if (contentUuids.containsKey(attributeContent + uuid)) {
                            contentUuid = contentUuids.get(attributeContent + uuid);
                        } else {
                            contentUuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeContentCommandGenerator(attributeContent, contentUuid, uuid));
                            contentUuids.put(attributeContent + uuid, contentUuid);
                        }
                        migrationCommands.add(attributeContent2ObjectCommandGenerator(UUID.randomUUID().toString(),
                                contentUuid,
                                "CERTIFICATE",
                                rows.getString("uuid"),
                                null,
                                null,
                                null,
                                null)
                        );
                    }
                }
            }
        }
        return migrationCommands;
    }

    private List<String> migrateLocationTable(Context context, List<String> availableConnectors) throws Exception {
        List<String> migrationCommands = new ArrayList<>();
        Map<String, String> definitionUuid = new HashMap<>();
        Map<String, String> contentUuids = new HashMap<>();
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT l.uuid, l.metadata, l.entity_instance_ref_uuid, a.connector_uuid FROM location l JOIN \"entity_instance_reference\" a ON a.uuid = l.entity_instance_ref_uuid  ORDER BY uuid")) {
                while (rows.next()) {
                    List<MetadataAttributeV2> attributes = V2AttributeMigrationUtils.getMetadataMigrationAttributes(rows.getString("metadata"));
                    if (attributes == null) {
                        continue;
                    }
                    for (MetadataAttributeV2 metadata : attributes) {
                        String attributeDefinition = AttributeDefinitionUtils.serialize(metadata);
                        String attributeContent = AttributeDefinitionUtils.serializeAttributeContent(metadata.getContent());
                        String uuid;
                        String connectorUuid = availableConnectors.contains(rows.getString("connector_uuid")) ? rows.getString("connector_uuid") : null;
                        if (definitionUuid.containsKey(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName())) {
                            uuid = definitionUuid.get(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName());
                        } else {
                            uuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeDefinitionCommandGenerator(attributeDefinition, uuid, connectorUuid, metadata.getName(), metadata.getType().toString(), metadata.getContentType().toString()));
                            definitionUuid.put(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName(), uuid);
                        }
                        String contentUuid;
                        if (contentUuids.containsKey(attributeContent + uuid)) {
                            contentUuid = contentUuids.get(attributeContent + uuid);
                        } else {
                            contentUuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeContentCommandGenerator(attributeContent, contentUuid, uuid));
                            contentUuids.put(attributeContent + uuid, contentUuid);
                        }
                        migrationCommands.add(attributeContent2ObjectCommandGenerator(UUID.randomUUID().toString(),
                                contentUuid,
                                "LOCATION",
                                rows.getString("uuid"),
                                null,
                                null,
                                null,
                                connectorUuid)
                        );
                    }
                }
            }
        }
        return migrationCommands;
    }

    private List<String> migrateCertificateLocationTable(Context context, List<String> availableConnectors) throws Exception {
        List<String> migrationCommands = new ArrayList<>();
        Map<String, String> definitionUuid = new HashMap<>();
        Map<String, String> contentUuids = new HashMap<>();
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT cl.location_uuid, cl.certificate_uuid, cl.metadata, a.connector_uuid, l.name FROM certificate_location cl JOIN \"location\" l ON cl.location_uuid = l.uuid JOIN \"entity_instance_reference\" a ON a.uuid = l.entity_instance_ref_uuid")) {
                while (rows.next()) {
                    List<MetadataAttributeV2> attributes = V2AttributeMigrationUtils.getMetadataMigrationAttributes(rows.getString("metadata"));
                    if (attributes == null) {
                        continue;
                    }
                    for (MetadataAttributeV2 metadata : attributes) {
                        String attributeDefinition = AttributeDefinitionUtils.serialize(metadata);
                        String attributeContent = AttributeDefinitionUtils.serializeAttributeContent(metadata.getContent());
                        String uuid;
                        String connectorUuid = availableConnectors.contains(rows.getString("connector_uuid")) ? rows.getString("connector_uuid") : null;
                        if (definitionUuid.containsKey(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName())) {
                            uuid = definitionUuid.get(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName());
                        } else {
                            uuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeDefinitionCommandGenerator(attributeDefinition, uuid, connectorUuid, metadata.getName(), metadata.getType().toString(), metadata.getContentType().toString()));
                            definitionUuid.put(availableConnectors.contains(rows.getString("connector_uuid")) + metadata.getName(), uuid);
                        }
                        String contentUuid;
                        if (contentUuids.containsKey(attributeContent + uuid)) {
                            contentUuid = contentUuids.get(attributeContent + uuid);
                        } else {
                            contentUuid = UUID.randomUUID().toString();
                            migrationCommands.add(attributeContentCommandGenerator(attributeContent, contentUuid, uuid));
                            contentUuids.put(attributeContent + uuid, contentUuid);
                        }
                        migrationCommands.add(attributeContent2ObjectCommandGenerator(UUID.randomUUID().toString(),
                                contentUuid,
                                "CERTIFICATE",
                                rows.getString("certificate_uuid"),
                                "LOCATION",
                                rows.getString("location_uuid"),
                                rows.getString("name"),
                                connectorUuid)
                        );
                    }
                }
            }
        }
        return migrationCommands;
    }

    private List<String> getAvailableConnectors(Context context) throws Exception {
        List<String> uuids = new ArrayList<>();
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT uuid FROM connector ORDER BY uuid")) {
                while (rows.next()) {
                    uuids.add(rows.getString("uuid"));
                }
            }
        }
        return uuids;
    }

    private String attributeDefinitionCommandGenerator(String definition, String uuid, String connectorUuid, String attributeName, String attributeType, String attributeContentType) {
        if (connectorUuid != null) {
            return "INSERT INTO \"attribute_definition\" (\"uuid\", \"i_author\", \"i_cre\", \"i_upd\", \"connector_uuid\", \"attribute_uuid\", \"attribute_name\", \"attribute_definition\", \"attribute_type\", \"attribute_content_type\", \"enabled\", \"global\", \"reference\") VALUES ('" + uuid + "', NULL, current_timestamp, current_timestamp, '" + connectorUuid + "', NULL, '" + attributeName + "', '" + definition + "', '" + attributeType + "', '" + attributeContentType + "', NULL, NULL, NULL);";
        } else {
            return "INSERT INTO \"attribute_definition\" (\"uuid\", \"i_author\", \"i_cre\", \"i_upd\", \"connector_uuid\", \"attribute_uuid\", \"attribute_name\", \"attribute_definition\", \"attribute_type\", \"attribute_content_type\", \"enabled\", \"global\", \"reference\") VALUES ('" + uuid + "', NULL, current_timestamp, current_timestamp, NULL, NULL, '" + attributeName + "', '" + definition + "', '" + attributeType + "', '" + attributeContentType + "', NULL, NULL, NULL);";
        }
    }

    private String attributeContentCommandGenerator(String content, String uuid, String definitionUuid) {
        return "INSERT INTO \"attribute_content\" (\"uuid\", \"attribute_definition_uuid\", \"attribute_content\") VALUES ('" + uuid + "', '" + definitionUuid + "', '" + content + "');";
    }

    private String attributeContent2ObjectCommandGenerator(String uuid, String contentUuid, String objectType, String objectUuid, String sourceObjectType, String sourceObjectUuid, String sourceObjectName, String connectorUuid) {
        if (connectorUuid != null) {
            return "INSERT INTO \"attribute_content_2_object\" (\"uuid\", \"connector_uuid\", \"attribute_content_uuid\", \"object_type\", \"object_uuid\", \"source_object_type\", \"source_object_uuid\", \"source_object_name\") VALUES ('" + uuid + "', '" + connectorUuid + "', '" + contentUuid + "', '" + objectType + "', '" + objectUuid + "', " + (sourceObjectType != null ? "'" + sourceObjectType + "', " : "NULL, ") + (sourceObjectUuid != null ? "'" + sourceObjectUuid + "'," : "NULL, ") + (sourceObjectName != null ? "'" + sourceObjectName + "'" : "NULL") + ");";
        } else {
            return "INSERT INTO \"attribute_content_2_object\" (\"uuid\", \"connector_uuid\", \"attribute_content_uuid\", \"object_type\", \"object_uuid\", \"source_object_type\", \"source_object_uuid\", \"source_object_name\") VALUES ('" + uuid + "', NULL, '" + contentUuid + "', '" + objectType + "', '" + objectUuid + "', " + (sourceObjectType != null ? "'" + sourceObjectType + "', " : "NULL, ") + (sourceObjectUuid != null ? "'" + sourceObjectUuid + "', " : "NULL, ")  + (sourceObjectName != null ? "'" + sourceObjectName + "'" : "NULL") + ");";
        }
    }

    private void createTables(Context context) throws Exception {
        String attributeDefinition = "CREATE TABLE \"attribute_definition\" ( \"uuid\" UUID NOT NULL, \"i_author\" VARCHAR NULL DEFAULT NULL, \"i_cre\" TIMESTAMP NULL DEFAULT NULL, \"i_upd\" TIMESTAMP NULL DEFAULT NULL, \"connector_uuid\" UUID NULL DEFAULT NULL, \"attribute_uuid\" UUID NULL DEFAULT NULL, \"attribute_name\" VARCHAR NOT NULL, \"attribute_type\" VARCHAR NOT NULL, \"attribute_content_type\" VARCHAR NOT NULL, \"attribute_definition\" TEXT NOT NULL, \"enabled\" BOOLEAN NULL DEFAULT NULL, \"global\" BOOLEAN NULL DEFAULT NULL, \"reference\" BOOLEAN NULL DEFAULT NULL, PRIMARY KEY (\"uuid\"), CONSTRAINT \"attribute_definition_to_connector_key\" FOREIGN KEY (\"connector_uuid\") REFERENCES \"connector\" (\"uuid\") ON UPDATE NO ACTION ON DELETE NO ACTION ) ;";
        String attributeContent = "CREATE TABLE \"attribute_content\" ( \"uuid\" UUID NOT NULL, \"attribute_definition_uuid\" UUID NOT NULL, \"attribute_content\" TEXT NOT NULL, PRIMARY KEY (\"uuid\"), CONSTRAINT \"attribute_content_to_attribute_definition_key\" FOREIGN KEY (\"attribute_definition_uuid\") REFERENCES \"attribute_definition\" (\"uuid\") ON UPDATE NO ACTION ON DELETE CASCADE ) ;";
        String attribute2Object = "CREATE TABLE \"attribute_content_2_object\" ( \"uuid\" UUID NOT NULL, \"connector_uuid\" UUID NULL DEFAULT NULL, \"attribute_content_uuid\" UUID NOT NULL, \"object_type\" VARCHAR NOT NULL, \"object_uuid\" UUID NOT NULL, \"source_object_type\" VARCHAR NULL DEFAULT NULL, \"source_object_uuid\" UUID NULL DEFAULT NULL, \"source_object_name\" VARCHAR NULL DEFAULT NULL, PRIMARY KEY (\"uuid\"), CONSTRAINT \"attribute_definition_to_connector_key\" FOREIGN KEY (\"connector_uuid\") REFERENCES \"connector\" (\"uuid\") ON UPDATE NO ACTION ON DELETE NO ACTION , CONSTRAINT \"attribute_object_to_attribute_content_key\" FOREIGN KEY (\"attribute_content_uuid\") REFERENCES \"attribute_content\" (\"uuid\") ON UPDATE NO ACTION ON DELETE CASCADE ) ;";
        String attributeRelation = "CREATE TABLE \"attribute_relation\" ( \"resource\" VARCHAR NOT NULL, \"function_group_code\" VARCHAR NULL DEFAULT NULL, \"kind\" VARCHAR NULL DEFAULT NULL, \"uuid\" UUID NOT NULL, \"attribute_definition_uuid\" UUID NULL DEFAULT NULL, CONSTRAINT \"attribute_relation_to_attribute_definition_key\" FOREIGN KEY (\"attribute_definition_uuid\") REFERENCES \"core\".\"attribute_definition\" (\"uuid\") ON UPDATE NO ACTION ON DELETE CASCADE ) ;";
        try (Statement select = context.getConnection().createStatement()) {
            executeCommands(select, List.of(attributeDefinition, attributeContent, attribute2Object, attributeRelation));
        }
    }

    private void cleanTables(Context context) throws Exception {
        String discovery = "ALTER TABLE discovery_history drop COLUMN meta;";
        String certificate = "ALTER TABLE certificate drop COLUMN meta;";
        String location = "ALTER TABLE location drop COLUMN metadata;";
        String certificateLocation = "ALTER TABLE certificate_location drop COLUMN metadata;";
        try (Statement select = context.getConnection().createStatement()) {
            executeCommands(select, List.of(discovery, certificate, location, certificateLocation));
        }
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for (String command : commands) {
            select.execute(command);
        }
    }
}
