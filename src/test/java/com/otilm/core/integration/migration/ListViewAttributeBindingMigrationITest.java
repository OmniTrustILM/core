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
            CREATE TABLE "list_view" (
                "uuid"    UUID PRIMARY KEY,
                "name"    VARCHAR NOT NULL,
                "columns" JSONB NOT NULL,
                "filters" JSONB
            );
            """;

    private static final String TEAM = "11111111-0000-4000-8000-000000000001";
    private static final String OWNER_FIRST = "22222222-0000-4000-8000-000000000002";
    private static final String OWNER_SECOND = "33333333-0000-4000-8000-000000000003";
    private static final String SAME_NAME_OTHER_TYPE = "44444444-0000-4000-8000-000000000004";
    private static final String TEAM_AS_TEXT = "55555555-0000-4000-8000-000000000005";

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
            statement.execute(definition(TEAM_AS_TEXT, "team", "CUSTOM", "TEXT"));
            statement.execute(definition(OWNER_SECOND, "owner", "META", "STRING"));
            statement.execute(definition(OWNER_FIRST, "owner", "META", "STRING"));
            statement.execute(definition(SAME_NAME_OTHER_TYPE, "deleted", "META", "STRING"));
            statement
                    .execute("INSERT INTO list_view (uuid, name, columns, filters) VALUES "
                            + "('aaaaaaaa-0000-4000-8000-000000000001', 'Filtered', '%s', '%s'), "
                                    .formatted(COLUMNS, FILTERS)
                            + "('aaaaaaaa-0000-4000-8000-000000000002', 'Plain', '%s', NULL)".formatted(COLUMNS));
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
            assertThat(bindingOf(columns.get(3))).containsExactly(OWNER_FIRST, OWNER_SECOND);
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
