package com.otilm.core.util;

import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DatabaseAttributeMigration {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseAttributeMigration.class);
    private static final ObjectMapper ATTRIBUTES_OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static Map<String, UUID> attributeNameDefinitionMapping = new HashMap<>();
    private static final Map<UUID, Map<String, UUID>> definitionsItemsContentMapping = new HashMap<>();

    // caching of connector UUIDs for different resources
    private static Map<UUID, UUID> tokensConnectorMapping;
    private static Map<UUID, UUID> entitiesConnectorMapping;
    private static Map<UUID, UUID> raProfilesConnectorMapping;
    private static Map<UUID, UUID> authoritiesConnectorMapping;

    public static void loadExistingDataAttributesDefinitions(Context context) throws SQLException {
        try (final Statement selectStatement = context.getConnection().createStatement()) {
            ResultSet rows = selectStatement.executeQuery("SELECT uuid, connector_uuid, name FROM attribute_definition WHERE type = 'DATA'");
            while (rows.next()) {
                UUID uuid = rows.getObject("uuid", UUID.class);
                UUID connectorUuid = rows.getObject("connector_uuid", UUID.class);
                String name = rows.getString("name");
                String attributeKey = String.join("|", connectorUuid != null ? connectorUuid.toString() : "", name);
                attributeNameDefinitionMapping.put(attributeKey, uuid);
            }
        }
    }

    public static void moveTableDataAttributes(Context context, Resource resource, String tableName, String[] columns, String[] operations, boolean[] fromConnector) throws SQLException, JsonProcessingException {
        logger.debug("Moving data attribute definitions for resource '{}', table '{}', columns [{}] and operations [{}]", resource.getLabel(), tableName, String.join(", ", columns), String.join(", ", operations));
        try (final Statement selectStatement = context.getConnection().createStatement();
             final PreparedStatement insertDefinitionStatement = context.getConnection().prepareStatement("INSERT INTO attribute_definition(uuid, connector_uuid, attribute_uuid, name, type, content_type, label, required, read_only, definition, operation, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?::jsonb,?,?,?)"); // 13 fields
             final PreparedStatement insertContentItemStatement = context.getConnection().prepareStatement("INSERT INTO attribute_content_item(uuid, attribute_definition_uuid, json) VALUES (?,?,?::jsonb)");
             final PreparedStatement insertObjectContentStatement = context.getConnection().prepareStatement("INSERT INTO attribute_content_2_object(uuid, connector_uuid, attribute_content_item_uuid, object_type, object_uuid, source_object_type, source_object_uuid, source_object_name, item_order) VALUES (?,?,?,?,?,?,?,?,?)")) {

            int definitionInsertsCount = 0;
            int contentItemsInsertsCount = 0;
            int contentObjectsInsertsCount = 0;
            ResultSet rows = selectStatement.executeQuery("SELECT * FROM " + tableName);
            while (rows.next()) {
                UUID objectUuid = rows.getObject("uuid", UUID.class);
                for (int i = 0; i < columns.length; i++) {
                    final String json = rows.getString(columns[i]);

                    // no attributes serialized
                    if (json == null) {
                        continue;
                    }

                    List<DataAttributeV2> attributes = AttributeDefinitionUtils.deserialize(json, DataAttributeV2.class);
                    Timestamp currentTimestamp = new Timestamp(System.currentTimeMillis());
                    for (DataAttributeV2 dataAttribute : attributes) {
                        // check if attribute was not deserialized from RequestAttribute
                        if (dataAttribute.getProperties() == null) {
                            dataAttribute.setContentType(AttributeContentType.OBJECT); // default for now
                            if (dataAttribute.getUuid() == null) {
                                dataAttribute.setUuid(UUID.randomUUID().toString());
                            }

                            DataAttributeProperties properties = new DataAttributeProperties();
                            properties.setLabel("");
                            properties.setVisible(true);
                            dataAttribute.setProperties(properties);
                            dataAttribute.setDescription(AttributeEngine.ATTRIBUTE_DEFINITION_FORCE_UPDATE_LABEL);
                        }

                        List<BaseAttributeContentV2<?>> dataAttributeContent = dataAttribute.getContent();
                        if (!dataAttribute.getProperties().isReadOnly()) {
                            dataAttribute.setContent(null);
                        }

                        // TODO: can be connector null for DATA attribute?
                        UUID connectorUuid = fromConnector[i] ? getConnectorUuidForResource(context, resource, rows) : null;

                        // create or get attribute definition
                        String attributeKey = String.join("|", connectorUuid != null ? connectorUuid.toString() : "", dataAttribute.getName());
                        UUID definitionUuid = attributeNameDefinitionMapping.get(attributeKey);
                        if (definitionUuid == null) {
                            definitionUuid = UUID.randomUUID();

                            ++definitionInsertsCount;
                            insertDefinitionStatement.setObject(1, definitionUuid);
                            insertDefinitionStatement.setObject(2, connectorUuid);
                            insertDefinitionStatement.setObject(3, UUID.fromString(dataAttribute.getUuid()));
                            insertDefinitionStatement.setString(4, dataAttribute.getName());
                            insertDefinitionStatement.setString(5, dataAttribute.getType().toString());
                            insertDefinitionStatement.setString(6, dataAttribute.getContentType().toString());
                            insertDefinitionStatement.setString(7, dataAttribute.getProperties().getLabel());
                            insertDefinitionStatement.setBoolean(8, dataAttribute.getProperties().isRequired());
                            insertDefinitionStatement.setBoolean(9, dataAttribute.getProperties().isReadOnly());
                            insertDefinitionStatement.setString(10, AttributeDefinitionUtils.serialize(dataAttribute));
                            insertDefinitionStatement.setString(11, operations[i]);
                            insertDefinitionStatement.setTimestamp(12, currentTimestamp);
                            insertDefinitionStatement.setTimestamp(13, currentTimestamp);
                            insertDefinitionStatement.addBatch();

                            attributeNameDefinitionMapping.put(attributeKey, definitionUuid);
                        }


                        // mapping serialized content to existing item UUID
                        Map<String, UUID> definitionItemsContentMapping = definitionsItemsContentMapping.get(definitionUuid);
                        if (definitionItemsContentMapping == null) {
                            definitionItemsContentMapping = new HashMap<>();
                            definitionsItemsContentMapping.put(definitionUuid, definitionItemsContentMapping);
                        }

                        // create content items for definition
                        for (int orderNo = 0; orderNo < dataAttributeContent.size(); orderNo++) {
                            BaseAttributeContentV2 attributeContent = dataAttributeContent.get(orderNo);
                            String serializedContent = ATTRIBUTES_OBJECT_MAPPER.writeValueAsString(attributeContent);
                            UUID contentItemUuid = definitionItemsContentMapping.get(serializedContent);
                            if (contentItemUuid == null) {
                                contentItemUuid = UUID.randomUUID();

                                ++contentItemsInsertsCount;
                                insertContentItemStatement.setObject(1, contentItemUuid);
                                insertContentItemStatement.setObject(2, definitionUuid);
                                insertContentItemStatement.setString(3, serializedContent);
                                insertContentItemStatement.addBatch();

                                definitionItemsContentMapping.put(serializedContent, contentItemUuid);
                            }

                            // assign content item to object
                            ++contentObjectsInsertsCount;
                            insertObjectContentStatement.setObject(1, UUID.randomUUID());
                            insertObjectContentStatement.setObject(2, connectorUuid);
                            insertObjectContentStatement.setObject(3, contentItemUuid);
                            insertObjectContentStatement.setString(4, resource.toString());
                            insertObjectContentStatement.setObject(5, objectUuid);
                            insertObjectContentStatement.setString(6, null);
                            insertObjectContentStatement.setObject(7, null);
                            insertObjectContentStatement.setString(8, null);
                            insertObjectContentStatement.setInt(9, orderNo);
                            insertObjectContentStatement.addBatch();
                        }
                    }
                }
            }

            logger.debug("Executing batch insert with {} data attribute definitions for resource '{}', table '{}', columns [{}] and operations [{}]", definitionInsertsCount, resource.getLabel(), tableName, String.join(", ", columns), String.join(", ", operations));
            insertDefinitionStatement.executeBatch();

            logger.debug("Executing batch insert with {} attribute content items.", contentItemsInsertsCount);
            insertContentItemStatement.executeBatch();

            logger.debug("Executing batch insert with {} attribute content items assigned to {} objects.", contentObjectsInsertsCount, resource.getLabel());
            insertObjectContentStatement.executeBatch();
        }

        // drop migrated columns
        try (Statement statement = context.getConnection().createStatement()) {
            for (String column : columns) {
                statement.addBatch("ALTER TABLE " + tableName + " DROP COLUMN " + column);
            }

            statement.executeBatch();
        }
    }

    private static UUID getConnectorUuidForResource(Context context, Resource resource, ResultSet rows) throws SQLException {
        switch (resource) {
            case CREDENTIAL, DISCOVERY, TOKEN -> {
                return rows.getObject("connector_uuid", UUID.class);
            }
            case ACME_PROFILE, SCEP_PROFILE, CERTIFICATE -> {
                if (raProfilesConnectorMapping == null) {
                    loadRaProfileConnectorMapping(context);
                }
                UUID raProfileUuid = rows.getObject("ra_profile_uuid", UUID.class);
                return raProfilesConnectorMapping == null ? null : raProfilesConnectorMapping.getOrDefault(raProfileUuid, null);
            }
            case RA_PROFILE -> {
                if (authoritiesConnectorMapping == null) {
                    authoritiesConnectorMapping = loadConnectorMapping(context, "authority_instance_reference");
                }
                UUID authorityUuid = rows.getObject("authority_instance_ref_uuid", UUID.class);
                return authoritiesConnectorMapping.get(authorityUuid);
            }
            case LOCATION -> {
                if (entitiesConnectorMapping == null) {
                    entitiesConnectorMapping = loadConnectorMapping(context, "entity_instance_reference");
                }
                UUID entityUuid = rows.getObject("entity_instance_ref_uuid", UUID.class);
                return entitiesConnectorMapping.get(entityUuid);
            }
            case TOKEN_PROFILE -> {
                if (tokensConnectorMapping == null) {
                    tokensConnectorMapping = loadConnectorMapping(context, "token_instance_reference");
                }
                UUID tokenUuid = rows.getObject("token_instance_ref_uuid", UUID.class);
                return tokensConnectorMapping.get(tokenUuid);
            }
            case CRYPTOGRAPHIC_KEY -> {
                if (tokensConnectorMapping == null) {
                    tokensConnectorMapping = loadConnectorMapping(context, "token_instance_reference");
                }
                UUID tokenUuid = rows.getObject("token_instance_uuid", UUID.class);
                return tokensConnectorMapping.get(tokenUuid);
            }
            default -> {
                return null;
            }
        }
    }

    private static void loadRaProfileConnectorMapping(Context context) throws SQLException {
        raProfilesConnectorMapping = new HashMap<>();
        try (final Statement selectStatement = context.getConnection().createStatement()) {
            ResultSet rows = selectStatement.executeQuery("SELECT ra.uuid AS uuid, a.connector_uuid AS connectorUuid FROM ra_profile AS ra JOIN authority_instance_reference AS a ON ra.authority_instance_ref_uuid = a.uuid");
            while (rows.next()) {
                UUID uuid = rows.getObject("uuid", UUID.class);
                UUID connectorUuid = rows.getObject("connectorUuid", UUID.class);
                raProfilesConnectorMapping.put(uuid, connectorUuid);
            }
        }
    }

    private static Map<UUID, UUID> loadConnectorMapping(Context context, String tableName) throws SQLException {
        Map<UUID, UUID> connectorMapping = new HashMap<>();
        try (final Statement selectStatement = context.getConnection().createStatement()) {
            ResultSet rows = selectStatement.executeQuery("SELECT uuid, connector_uuid FROM " + tableName);
            while (rows.next()) {
                UUID uuid = rows.getObject("uuid", UUID.class);
                UUID connectorUuid = rows.getObject("connector_uuid", UUID.class);
                connectorMapping.put(uuid, connectorUuid);
            }
        }
        return connectorMapping;
    }

}
