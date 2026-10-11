package com.otilm.core.integration.migration;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202610111000__attribute_definition_unique_key.sql} in a scratch schema holding stubs of the tables it
 * rewrites, and asserts that duplicate definitions fold together with everything that refers to them. The regular test
 * bootstrap generates its schema from the entities, so nothing else executes this file; the last test checks that the
 * keys the migration adds behave as the ones the entity declares.
 */
class AttributeDefinitionUniqueKeyMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610111000__attribute_definition_unique_key.sql";
    private static final String SCRATCH_SCHEMA = "attribute_definition_unique_key_migration_check";
    private static final String CONNECTOR_ONE = "c0000000-0000-0000-0000-000000000001";
    private static final String CONNECTOR_TWO = "c0000000-0000-0000-0000-000000000002";
    private static final String CONNECTOR_THREE = "c0000000-0000-0000-0000-000000000003";
    private static final String ATTRIBUTE = "a0000000-0000-0000-0000-000000000001";
    private static final String OTHER_ATTRIBUTE = "a0000000-0000-0000-0000-000000000002";
    private static final String KEPT = "d0000000-0000-0000-0000-000000000001";
    private static final String DUPLICATE = "d0000000-0000-0000-0000-000000000002";
    private static final String THIRD = "d0000000-0000-0000-0000-000000000003";
    private static final String KEPT_VALUE = "e0000000-0000-0000-0000-000000000001";
    private static final String DUPLICATE_VALUE = "e0000000-0000-0000-0000-000000000002";
    private static final String OTHER_VALUE = "e0000000-0000-0000-0000-000000000003";
    private static final String ENCRYPTED_VALUE = "e0000000-0000-0000-0000-000000000004";
    private static final String THIRD_VALUE = "e0000000-0000-0000-0000-000000000005";
    private static final String OBJECT_ONE = "0b000000-0000-0000-0000-000000000001";
    private static final String OBJECT_TWO = "0b000000-0000-0000-0000-000000000002";
    private static final String OBJECT_THREE = "0b000000-0000-0000-0000-000000000003";
    private static final String EARLIER = "2026-10-01 10:00:00";
    private static final String LATER = "2026-10-01 10:00:01";
    private static final String LATEST = "2026-10-01 10:00:02";
    private static final String TABLE_STUBS = """
            CREATE TABLE "attribute_definition" (
                "uuid" UUID PRIMARY KEY,
                "connector_uuid" UUID,
                "attribute_uuid" UUID NOT NULL,
                "name" TEXT NOT NULL,
                "type" TEXT NOT NULL,
                "content_type" TEXT,
                "label" TEXT NOT NULL,
                "visible" BOOLEAN NOT NULL DEFAULT TRUE,
                "version" INTEGER NOT NULL DEFAULT 2,
                "definition" JSONB NOT NULL,
                "global" BOOLEAN,
                "operation" TEXT,
                "protection_level" VARCHAR,
                "created_at" TIMESTAMP NOT NULL,
                "updated_at" TIMESTAMP NOT NULL
            );
            CREATE TABLE "attribute_content_item" (
                "uuid" UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL REFERENCES "attribute_definition" ("uuid")
                    ON UPDATE CASCADE ON DELETE RESTRICT,
                "json" JSONB NOT NULL,
                "encrypted_data" VARCHAR,
                "json_digest" BYTEA GENERATED ALWAYS AS (CASE WHEN "encrypted_data" IS NULL
                    THEN sha256(decode(replace("json"::TEXT, chr(92), chr(92) || chr(92)), 'escape')) END) STORED,
                CONSTRAINT "uq_attribute_content_item_value" UNIQUE ("attribute_definition_uuid", "json_digest")
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid" UUID PRIMARY KEY,
                "attribute_content_item_uuid" UUID NOT NULL REFERENCES "attribute_content_item" ("uuid")
                    ON UPDATE CASCADE ON DELETE RESTRICT,
                "object_type" VARCHAR NOT NULL,
                "object_uuid" UUID NOT NULL,
                "connector_uuid" UUID,
                "source_object_type" VARCHAR,
                "source_object_uuid" UUID,
                "source_object_name" VARCHAR,
                "item_order" INTEGER,
                "purpose" VARCHAR,
                "object_version" INTEGER
            );
            CREATE TABLE "attribute_relation" (
                "uuid" UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL REFERENCES "attribute_definition" ("uuid") ON DELETE CASCADE,
                "resource" VARCHAR NOT NULL,
                "function_group_code" VARCHAR,
                "kind" VARCHAR
            );
            CREATE TABLE "notification_instance_mapped_attributes" (
                "uuid" UUID PRIMARY KEY,
                "notification_instance_ref_uuid" UUID NOT NULL,
                "attribute_definition_uuid" UUID NOT NULL REFERENCES "attribute_definition" ("uuid") ON DELETE CASCADE,
                "mapping_attribute_uuid" UUID,
                "mapping_attribute_name" TEXT
            );
            CREATE TABLE "list_view" (
                "uuid" UUID PRIMARY KEY,
                "resource" VARCHAR NOT NULL,
                "columns" JSONB NOT NULL,
                "filters" JSONB,
                "sort" JSONB,
                "sort_attribute_definition_uuids" UUID[]
            )
            """;

    @Autowired
    private DataSource dataSource;
    @Autowired
    private ConnectorRepository connectorRepository;

    @FunctionalInterface
    private interface SqlWork {
        void run(Statement statement) throws Exception;
    }

    @Test
    void aMetadataPairFoldsWithItsValuesMappingsAndReferences() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "totalUrls", false, "INTEGER", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_ONE, ATTRIBUTE, "totalUrls", false, "INTEGER", null,
                    LATER);
            value(statement, KEPT_VALUE, KEPT, "{\"data\": 5}");
            value(statement, DUPLICATE_VALUE, DUPLICATE, "{\"data\": 5}");
            value(statement, OTHER_VALUE, DUPLICATE, "{\"data\": 7}");
            encryptedValue(statement, ENCRYPTED_VALUE, DUPLICATE);
            mapping(statement, KEPT_VALUE, OBJECT_ONE);
            mapping(statement, DUPLICATE_VALUE, OBJECT_TWO);
            // Object one held both copies of the value: after the fold it holds it once.
            mapping(statement, DUPLICATE_VALUE, OBJECT_ONE);
            mapping(statement, OTHER_VALUE, OBJECT_THREE);
            mapping(statement, ENCRYPTED_VALUE, OBJECT_THREE);
            relation(statement, KEPT, "CERTIFICATE");
            relation(statement, DUPLICATE, "CERTIFICATE");
            relation(statement, DUPLICATE, "DISCOVERY");
            statement
                    .execute("INSERT INTO notification_instance_mapped_attributes"
                            + " (uuid, notification_instance_ref_uuid, attribute_definition_uuid)"
                            + " VALUES (gen_random_uuid(), gen_random_uuid(), '" + DUPLICATE + "')");

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition")).isEqualTo(1);
            assertThat(count(statement,
                    "SELECT count(*) FROM attribute_content_item WHERE uuid = '" + DUPLICATE_VALUE + "'")).isZero();
            assertThat(count(statement,
                    "SELECT count(*) FROM attribute_content_item WHERE attribute_definition_uuid = '" + KEPT + "'"))
                    .isEqualTo(3);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object WHERE"
                    + " attribute_content_item_uuid = '" + KEPT_VALUE + "' AND object_uuid = '" + OBJECT_ONE + "'"))
                    .isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object WHERE"
                    + " attribute_content_item_uuid = '" + KEPT_VALUE + "' AND object_uuid = '" + OBJECT_TWO + "'"))
                    .isEqualTo(1);
            assertThat(count(statement,
                    "SELECT count(*) FROM attribute_relation WHERE attribute_definition_uuid = '" + KEPT + "'"))
                    .isEqualTo(2);
            assertThat(count(statement, "SELECT count(*) FROM notification_instance_mapped_attributes"
                    + " WHERE attribute_definition_uuid = '" + KEPT + "'")).isEqualTo(1);
        });
    }

    @Test
    void threeDuplicatesSharingAValueTheKeptRowLacksFoldOntoOneValue() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, LATER);
            definition(statement, THIRD, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, LATEST);
            value(statement, DUPLICATE_VALUE, DUPLICATE, "{\"data\": \"x\"}");
            value(statement, THIRD_VALUE, THIRD, "{\"data\": \"x\"}");
            mapping(statement, DUPLICATE_VALUE, OBJECT_ONE);
            mapping(statement, THIRD_VALUE, OBJECT_TWO);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_content_item")).isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_item WHERE uuid = '" + DUPLICATE_VALUE
                    + "' AND attribute_definition_uuid = '" + KEPT + "'")).isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object WHERE"
                    + " attribute_content_item_uuid = '" + DUPLICATE_VALUE + "'")).isEqualTo(2);
        });
    }

    @Test
    void globalMetadataUnderTwoUuidsFolds_andAGlobalDeclaredDifferentlyIsDetached() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "source", true, "STRING", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_TWO, OTHER_ATTRIBUTE, "source", true, "STRING", null,
                    LATER);
            definition(statement, THIRD, "META", CONNECTOR_THREE, OTHER_ATTRIBUTE, "source", true, "INTEGER", null,
                    LATEST);
            value(statement, THIRD_VALUE, THIRD, "{\"data\": 3}");
            mapping(statement, THIRD_VALUE, OBJECT_ONE);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE uuid = '" + DUPLICATE + "'"))
                    .isZero();
            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE uuid = '" + THIRD
                    + "' AND connector_uuid IS NULL AND global IS FALSE")).isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_item WHERE uuid = '" + THIRD_VALUE
                    + "' AND attribute_definition_uuid = '" + THIRD + "'")).isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE global IS TRUE")).isEqualTo(1);
        });
    }

    /**
     * The global row survives although the connector row is older: other connectors share it and the API addresses it
     * by its UUID.
     */
    @Test
    void aGlobalAndAConnectorRowWithTheSameKeyFoldIntoTheGlobalRow() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_ONE, ATTRIBUTE, "source", true, "STRING", null, LATER);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition")).isEqualTo(1);
            assertThat(count(statement,
                    "SELECT count(*) FROM attribute_definition WHERE uuid = '" + DUPLICATE + "' AND global IS TRUE"))
                    .isEqualTo(1);
        });
    }

    @Test
    void platformDataDefinitionsFold_andADataPairKeepsTheRowWithAnOperation() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "DATA", null, ATTRIBUTE, "platform", false, "STRING", "issue", EARLIER);
            definition(statement, DUPLICATE, "DATA", null, ATTRIBUTE, "platform", false, "STRING", "issue", LATER);
            String older = "d0000000-0000-0000-0000-000000000011";
            String claimed = "d0000000-0000-0000-0000-000000000012";
            definition(statement, older, "DATA", CONNECTOR_ONE, OTHER_ATTRIBUTE, "raProfile", false, "STRING", null,
                    EARLIER);
            definition(statement, claimed, "DATA", CONNECTOR_ONE, OTHER_ATTRIBUTE, "raProfile", false, "STRING",
                    "issue", LATER);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE name = 'platform'"))
                    .isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE name = 'raProfile'"))
                    .isEqualTo(1);
            assertThat(count(statement, "SELECT count(*) FROM attribute_definition WHERE uuid = '" + claimed + "'"))
                    .isEqualTo(1);
        });
    }

    @Test
    void orphanedMetadataOfDeletedConnectorsIsLeftAlone() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", null, ATTRIBUTE, "totalUrls", false, "INTEGER", null, EARLIER);
            definition(statement, DUPLICATE, "META", null, ATTRIBUTE, "totalUrls", false, "INTEGER", null, LATER);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition")).isEqualTo(2);
        });
    }

    @Test
    void aDataPairThatReadsItsValuesDifferentlyStopsTheMigration() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "DATA", CONNECTOR_ONE, ATTRIBUTE, "port", false, "STRING", null, EARLIER);
            definition(statement, DUPLICATE, "DATA", CONNECTOR_ONE, ATTRIBUTE, "port", false, "INTEGER", null, LATER);

            assertThatThrownBy(() -> migrate(statement))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining(DUPLICATE);
        });
    }

    @Test
    void aListViewIsRebound_andAFilterValueNamingADuplicateIsKept() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_ONE, ATTRIBUTE, "source", false, "STRING", null, LATER);
            statement
                    .execute(
                            """
                                    INSERT INTO list_view (uuid, resource, columns, filters, sort_attribute_definition_uuids)
                                    VALUES (gen_random_uuid(), 'CERTIFICATE',
                                        '[{"fieldIdentifier": "source|string", "attributeDefinitionUuids": ["%s"]}]',
                                        '[{"fieldIdentifier": "source|string", "attributeDefinitionUuids": ["%s", "%s"], "value": "%s"}]',
                                        ARRAY['%s']::UUID[])
                                    """
                                    .formatted(DUPLICATE, KEPT, DUPLICATE, DUPLICATE, DUPLICATE));

            migrate(statement);

            assertThat(text(statement, "SELECT columns -> 0 -> 'attributeDefinitionUuids' FROM list_view"))
                    .isEqualTo("[\"" + KEPT + "\"]");
            assertThat(text(statement, "SELECT filters -> 0 -> 'attributeDefinitionUuids' FROM list_view"))
                    .isEqualTo("[\"" + KEPT + "\"]");
            assertThat(text(statement, "SELECT filters -> 0 ->> 'value' FROM list_view")).isEqualTo(DUPLICATE);
            assertThat(text(statement, "SELECT sort_attribute_definition_uuids::TEXT FROM list_view"))
                    .isEqualTo("{" + KEPT + "}");
        });
    }

    @Test
    void aDatabaseWithoutDuplicatesOnlyGainsTheKeys() throws Exception {
        inScratchSchema(statement -> {
            definition(statement, KEPT, "META", CONNECTOR_ONE, ATTRIBUTE, "totalUrls", false, "INTEGER", null, EARLIER);
            definition(statement, DUPLICATE, "META", CONNECTOR_TWO, ATTRIBUTE, "totalUrls", false, "INTEGER", null,
                    LATER);
            definition(statement, THIRD, "META", CONNECTOR_ONE, OTHER_ATTRIBUTE, "source", true, "STRING", null,
                    LATEST);
            value(statement, KEPT_VALUE, KEPT, "{\"data\": 5}");
            mapping(statement, KEPT_VALUE, OBJECT_ONE);

            migrate(statement);

            assertThat(count(statement, "SELECT count(*) FROM attribute_definition")).isEqualTo(3);
            assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object")).isEqualTo(1);
            assertThat(count(statement,
                    "SELECT count(*) FROM pg_constraint WHERE conname IN"
                            + " ('uq_attribute_definition_key', 'uq_attribute_definition_global_name')"
                            + " AND connamespace = '" + SCRATCH_SCHEMA + "'::regnamespace"))
                    .isEqualTo(2);
        });
    }

    @Test
    void theMigratedKeysBehaveAsTheEntityKeys() throws Exception {
        String connectorOne = newConnector();
        String connectorTwo = newConnector();
        inScratchSchema(statement -> {
            migrate(statement);
            assertKeys(statement.getConnection(), connectorOne, connectorTwo);
        });
        // The regular test schema, generated from the entity's annotations.
        try (Connection connection = dataSource.getConnection()) {
            assertKeys(connection, connectorOne, connectorTwo);
        }
    }

    private void assertKeys(Connection connection, String connectorOne, String connectorTwo) throws SQLException {
        String suffix = UUID.randomUUID().toString();
        String attribute = UUID.randomUUID().toString();
        String otherAttribute = UUID.randomUUID().toString();
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            assertCollide(connection, new Row("META", connectorOne, attribute, "metadata-" + suffix, false),
                    new Row("META", connectorOne, attribute, "metadata-" + suffix, false));
            assertCoexist(connection, new Row("META", null, attribute, "orphan-" + suffix, false),
                    new Row("META", null, attribute, "orphan-" + suffix, false));
            assertCollide(connection, new Row("DATA", null, attribute, "platform-" + suffix, false),
                    new Row("DATA", null, attribute, "platform-" + suffix, false));
            assertCollide(connection, new Row("META", connectorOne, attribute, "shared-" + suffix, true),
                    new Row("META", connectorTwo, otherAttribute, "shared-" + suffix, true));
            assertCoexist(connection, new Row("META", connectorOne, attribute, "scoped-" + suffix, true),
                    new Row("META", connectorTwo, otherAttribute, "scoped-" + suffix, false));
        } finally {
            connection.rollback();
            connection.setAutoCommit(autoCommit);
        }
    }

    private record Row(String type, String connector, String attribute, String name, boolean global) {
    }

    private static void assertCollide(Connection connection, Row first, Row second) throws SQLException {
        insert(connection, first);
        Savepoint beforeSecond = connection.setSavepoint();
        assertThatThrownBy(() -> insert(connection, second))
                .isInstanceOf(SQLException.class)
                .satisfies(e -> assertThat(((SQLException) e).getSQLState()).isEqualTo("23505"));
        connection.rollback(beforeSecond);
    }

    private static void assertCoexist(Connection connection, Row first, Row second) throws SQLException {
        insert(connection, first);
        insert(connection, second);
    }

    private static void insert(Connection connection, Row row) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement("""
                INSERT INTO attribute_definition (uuid, connector_uuid, attribute_uuid, name, type, content_type, label,
                    visible, version, definition, global, created_at, updated_at)
                VALUES (gen_random_uuid(), ?, ?, ?, ?, 'STRING', ?, TRUE, 2, CAST('{}' AS jsonb), ?, now(), now())
                """)) {
            if (row.connector() == null) {
                insert.setNull(1, Types.OTHER);
            } else {
                insert.setObject(1, UUID.fromString(row.connector()));
            }
            insert.setObject(2, UUID.fromString(row.attribute()));
            insert.setString(3, row.name());
            insert.setString(4, row.type());
            insert.setString(5, row.name());
            insert.setBoolean(6, row.global());
            insert.executeUpdate();
        }
    }

    private String newConnector() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        return connectorRepository.save(connector).getUuid().toString();
    }

    private void inScratchSchema(SqlWork work) throws Exception {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            try {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                work.run(statement);
            } finally {
                // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                // must not point at the schema this drops.
                statement.execute("RESET search_path");
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            }
        }
    }

    /** In one transaction, as Flyway runs it: the migration's table lock needs one. */
    private static void migrate(Statement statement) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        Connection connection = statement.getConnection();
        connection.setAutoCommit(false);
        try {
            statement.execute(migration);
            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private static void definition(Statement statement, String uuid, String type, String connector, String attribute,
            String name, boolean global, String contentType, String operation, String createdAt) throws SQLException {
        statement
                .execute(
                        """
                                INSERT INTO attribute_definition (uuid, connector_uuid, attribute_uuid, name, type, content_type, label,
                                    definition, global, operation, created_at, updated_at)
                                VALUES ('%s', %s, '%s', '%s', '%s', '%s', '%s', '{}', %s, %s, '%s', '%s')
                                """
                                .formatted(uuid, literal(connector), attribute, name, type, contentType, name, global,
                                        literal(operation), createdAt, createdAt));
    }

    private static void value(Statement statement, String uuid, String definition, String json) throws SQLException {
        statement
                .execute("INSERT INTO attribute_content_item (uuid, attribute_definition_uuid, json) VALUES ('" + uuid
                        + "', '" + definition + "', '" + json + "')");
    }

    private static void encryptedValue(Statement statement, String uuid, String definition) throws SQLException {
        statement
                .execute("INSERT INTO attribute_content_item (uuid, attribute_definition_uuid, json, encrypted_data)"
                        + " VALUES ('" + uuid + "', '" + definition + "', '{\"contentType\": \"string\"}', 'cipher')");
    }

    private static void mapping(Statement statement, String item, String object) throws SQLException {
        statement
                .execute("INSERT INTO attribute_content_2_object (uuid, attribute_content_item_uuid, object_type,"
                        + " object_uuid, item_order) VALUES (gen_random_uuid(), '" + item + "', 'CERTIFICATE', '"
                        + object + "', 0)");
    }

    private static void relation(Statement statement, String definition, String resource) throws SQLException {
        statement
                .execute("INSERT INTO attribute_relation (uuid, attribute_definition_uuid, resource)"
                        + " VALUES (gen_random_uuid(), '" + definition + "', '" + resource + "')");
    }

    private static String literal(String value) {
        return value == null ? "NULL" : "'" + value + "'";
    }

    private static long count(Statement statement, String sql) throws SQLException {
        try (ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static String text(Statement statement, String sql) throws SQLException {
        try (ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
