package com.otilm.core.integration.migration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610021000__list_view_attribute_binding.sql} as Flyway will, against views stored before their
 * attribute entries carried a binding. Nothing else in the suite executes the file: the test bootstrap generates its
 * schema from the entities.
 */
class ListViewAttributeBindingMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610021000__list_view_attribute_binding.sql";

    private static final String SCRATCH_SCHEMA = "list_view_attribute_binding_check";

    private static final String STUB = """
            CREATE TABLE "attribute_definition" (
                "uuid"         UUID PRIMARY KEY,
                "name"         VARCHAR NOT NULL,
                "type"         VARCHAR NOT NULL,
                "content_type" VARCHAR
            );
            CREATE TABLE "attribute_relation" (
                "uuid"                      UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL,
                "resource"                  VARCHAR
            );
            CREATE TABLE "attribute_content_item" (
                "uuid"                      UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid"                        UUID PRIMARY KEY,
                "attribute_content_item_uuid" UUID NOT NULL,
                "object_type"                 VARCHAR NOT NULL
            );
            CREATE TABLE "list_view" (
                "uuid"     UUID PRIMARY KEY,
                "resource" VARCHAR NOT NULL,
                "name"     VARCHAR NOT NULL,
                "columns"  JSONB NOT NULL,
                "filters"  JSONB,
                "sort"     JSONB
            );
            """;

    private static final String TEAM = "11111111-0000-4000-8000-000000000001";
    private static final String OWNER_FIRST = "22222222-0000-4000-8000-000000000002";
    private static final String OWNER_SECOND = "33333333-0000-4000-8000-000000000003";
    private static final String SAME_NAME_OTHER_TYPE = "44444444-0000-4000-8000-000000000004";
    private static final String TEAM_AS_TEXT = "55555555-0000-4000-8000-000000000005";
    private static final String OWNER_ON_KEYS = "66666666-0000-4000-8000-000000000006";
    private static final String TEAM_ON_KEYS = "77777777-0000-4000-8000-000000000007";

    private static final String COLUMNS = """
            [{"fieldSource":"property","fieldIdentifier":"COMMON_NAME"},
             {"fieldSource":"custom","fieldIdentifier":"team|STRING","label":"Owning team"},
             {"fieldSource":"custom","fieldIdentifier":"deleted|STRING"},
             {"fieldSource":"meta","fieldIdentifier":"owner|STRING"},
             {"fieldSource":"data","fieldIdentifier":"team|STRING"}]""";

    private static final String FILTERS = """
            [{"fieldSource":"custom","fieldIdentifier":"team|STRING","condition":"EQUALS","value":"pki"},
             {"fieldSource":"property","fieldIdentifier":"COMMON_NAME","condition":"CONTAINS","value":"a"},
             {"fieldSource":"custom","fieldIdentifier":"deleted|STRING","condition":"EMPTY"}]""";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private DataSource dataSource;

    @Test
    void theMigrationBindsEveryStoredAttributeEntryWithoutLosingAny() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                givenViewsStoredBeforeBinding(connection);

                applyMigration(connection);

                assertColumnsAreBoundInPlace(connection);
                assertFiltersAreBoundInPlace(connection);
                assertAViewWithoutFiltersStillHasNone(connection);
                assertOrderingsAreBound(connection);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void givenViewsStoredBeforeBinding(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(STUB);
            statement.execute(definition(TEAM, "team", "CUSTOM", "STRING"));
            statement.execute(relation(TEAM, "CERTIFICATE"));
            statement.execute(definition(TEAM_AS_TEXT, "team", "CUSTOM", "TEXT"));
            statement.execute(relation(TEAM_AS_TEXT, "CERTIFICATE"));
            statement.execute(definition(OWNER_SECOND, "owner", "META", "STRING"));
            statement.execute(contentOn(OWNER_SECOND, "CERTIFICATE"));
            statement.execute(definition(OWNER_FIRST, "owner", "META", "STRING"));
            statement.execute(contentOn(OWNER_FIRST, "CERTIFICATE"));
            statement.execute(definition(OWNER_ON_KEYS, "owner", "META", "STRING"));
            statement.execute(contentOn(OWNER_ON_KEYS, "CRYPTOGRAPHIC_KEY"));
            statement.execute(definition(TEAM_ON_KEYS, "team", "DATA", "STRING"));
            statement.execute(contentOn(TEAM_ON_KEYS, "CRYPTOGRAPHIC_KEY"));
            statement.execute(definition(SAME_NAME_OTHER_TYPE, "deleted", "META", "STRING"));
            statement.execute(contentOn(SAME_NAME_OTHER_TYPE, "CERTIFICATE"));
            statement
                    .execute("INSERT INTO list_view (uuid, resource, name, columns, filters, sort) VALUES "
                            + "('aaaaaaaa-0000-4000-8000-000000000001', 'CERTIFICATE', 'Filtered', '%s', '%s', '%s'), "
                                    .formatted(COLUMNS, FILTERS, sort("meta", "owner|STRING"))
                            + "('aaaaaaaa-0000-4000-8000-000000000002', 'CERTIFICATE', 'Plain', '%s', NULL, '%s'), "
                                    .formatted(COLUMNS, sort("property", "COMMON_NAME"))
                            + "('aaaaaaaa-0000-4000-8000-000000000003', 'CRYPTOGRAPHIC_KEY', 'Keys', '%s', NULL, NULL), "
                                    .formatted(COLUMNS)
                            + "('aaaaaaaa-0000-4000-8000-000000000004', 'CERTIFICATE', 'Orphaned', '%s', NULL, '%s')"
                                    .formatted(COLUMNS, sort("custom", "deleted|STRING")));
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }

    private void assertColumnsAreBoundInPlace(Connection connection) throws Exception {
        for (String view : List.of("Filtered", "Plain")) {
            JsonNode columns = json(connection, "SELECT columns FROM list_view WHERE name = '%s'".formatted(view));

            assertThat(identifiersOf(columns))
                    .containsExactly("COMMON_NAME", "team|STRING", "deleted|STRING", "owner|STRING", "team|STRING");
            assertThat(columns.get(0).has("attributeDefinitionUuids"))
                    .describedAs("a property column names no attribute definition")
                    .isFalse();
            assertThat(bindingOf(columns.get(1))).containsExactly(TEAM);
            assertThat(columns.get(1).get("label").asText()).isEqualTo("Owning team");
            assertThat(bindingOf(columns.get(2)))
                    .describedAs("a definition of another attribute type does not back a custom column")
                    .isEmpty();
            assertThat(bindingOf(columns.get(3)))
                    .describedAs("only the definitions on the view's resource, not the one on keys")
                    .containsExactly(OWNER_FIRST, OWNER_SECOND);
            assertThat(bindingOf(columns.get(4)))
                    .describedAs("a custom definition does not back a data column of the same name")
                    .isEmpty();
        }
    }

    private void assertFiltersAreBoundInPlace(Connection connection) throws Exception {
        JsonNode filters = json(connection, "SELECT filters FROM list_view WHERE name = 'Filtered'");

        assertThat(identifiersOf(filters)).containsExactly("team|STRING", "COMMON_NAME", "deleted|STRING");
        assertThat(bindingOf(filters.get(0))).containsExactly(TEAM);
        assertThat(filters.get(0).get("value").asText()).isEqualTo("pki");
        assertThat(filters.get(1).has("attributeDefinitionUuids")).isFalse();
        assertThat(bindingOf(filters.get(2))).isEmpty();
    }

    private void assertOrderingsAreBound(Connection connection) throws Exception {
        assertThat(sortBindingOf(connection, "Filtered")).isEqualTo("{%s,%s}".formatted(OWNER_FIRST, OWNER_SECOND));
        assertThat(sortBindingOf(connection, "Plain"))
                .describedAs("a property ordering names no attribute definition")
                .isNull();
        assertThat(sortBindingOf(connection, "Keys")).isNull();
        assertThat(sortBindingOf(connection, "Orphaned"))
                .describedAs("an ordering whose attribute is already gone is bound to nothing, not left unbound")
                .isEqualTo("{}");
        JsonNode keyColumns = json(connection, "SELECT columns FROM list_view WHERE name = 'Keys'");
        assertThat(bindingOf(keyColumns.get(1)))
                .describedAs("the custom attribute is related to certificates, not to keys")
                .isEmpty();
        assertThat(bindingOf(keyColumns.get(3))).containsExactly(OWNER_ON_KEYS);
        assertThat(bindingOf(keyColumns.get(4))).containsExactly(TEAM_ON_KEYS);
    }

    private static String sortBindingOf(Connection connection, String view) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement
                        .executeQuery("SELECT sort_attribute_definition_uuids FROM list_view WHERE name = '%s'"
                                .formatted(view))) {
            assertThat(rows.next()).isTrue();
            return rows.getString(1);
        }
    }

    private void assertAViewWithoutFiltersStillHasNone(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT filters FROM list_view WHERE name = 'Plain'")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getString(1)).isNull();
        }
    }

    private static String definition(String uuid, String name, String type, String contentType) {
        return "INSERT INTO attribute_definition (uuid, name, type, content_type) VALUES ('%s', '%s', '%s', '%s')"
                .formatted(uuid, name, type, contentType);
    }

    private static String relation(String definition, String resource) {
        return "INSERT INTO attribute_relation (uuid, attribute_definition_uuid, resource) VALUES ('%s', '%s', '%s')"
                .formatted(UUID.randomUUID(), definition, resource);
    }

    private static String contentOn(String definition, String objectType) {
        UUID item = UUID.randomUUID();
        return ("INSERT INTO attribute_content_item (uuid, attribute_definition_uuid) VALUES ('%s', '%s');"
                + "INSERT INTO attribute_content_2_object (uuid, attribute_content_item_uuid, object_type) "
                + "VALUES ('%s', '%s', '%s')").formatted(item, definition, UUID.randomUUID(), item, objectType);
    }

    private static String sort(String fieldSource, String fieldIdentifier) {
        return "{\"fieldSource\":\"%s\",\"fieldIdentifier\":\"%s\",\"direction\":\"asc\"}"
                .formatted(fieldSource, fieldIdentifier);
    }

    private JsonNode json(Connection connection, String sql) throws Exception {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            assertThat(rows.next()).isTrue();
            return mapper.readTree(rows.getString(1));
        }
    }

    private static List<String> identifiersOf(JsonNode entries) {
        List<String> identifiers = new ArrayList<>();
        entries.forEach(entry -> identifiers.add(entry.get("fieldIdentifier").asText()));
        return identifiers;
    }

    private static List<String> bindingOf(JsonNode entry) {
        assertThat(entry.has("attributeDefinitionUuids")).isTrue();
        List<String> uuids = new ArrayList<>();
        entry.get("attributeDefinitionUuids").forEach(uuid -> uuids.add(uuid.asText()));
        return uuids;
    }
}
