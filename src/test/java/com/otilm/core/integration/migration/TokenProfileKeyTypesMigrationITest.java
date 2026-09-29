package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202609251200__token_profile_importable_key_types.sql} as Flyway will, against the token profile table as
 * the migrations before it leave it. The test bootstrap generates its schema from the entities, so nothing else
 * executes the file; what needs proving is that the renamed counter keeps its value.
 */
class TokenProfileKeyTypesMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609251200__token_profile_importable_key_types.sql";

    private static final String SCRATCH_SCHEMA = "token_profile_key_types_migration_check";

    private static final String TOKEN_PROFILE_STUB = """
            CREATE TABLE "token_profile" (
                "uuid"                          UUID PRIMARY KEY,
                "exportable_key_types"          JSONB,
                "exportable_key_types_revision" INTEGER NOT NULL DEFAULT 0
            );
            """;

    private static final String EXPORT_ANSWER = "[{\"algorithms\": [\"RSA\"], \"keyRequestType\": \"keyPair\"}]";

    @Autowired
    private DataSource dataSource;

    @Test
    void theRevisionKeepsItsCountAndTheImportAnswerStartsUnknown() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                givenAProfileAskedThreeChangesAgo(connection);

                applyMigration(connection);

                try (Statement statement = connection.createStatement();
                        ResultSet row = statement
                                .executeQuery("SELECT key_types_revision, exportable_key_types::text,"
                                        + " importable_key_types FROM token_profile")) {
                    assertThat(row.next()).isTrue();
                    assertThat(row.getInt(1)).isEqualTo(3);
                    assertThat(row.getString(2)).isEqualTo(EXPORT_ANSWER);
                    assertThat(row.getString(3)).isNull();
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void givenAProfileAskedThreeChangesAgo(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(TOKEN_PROFILE_STUB);
            statement
                    .execute("INSERT INTO token_profile (uuid, exportable_key_types, exportable_key_types_revision)"
                            + " VALUES ('11111111-0000-4000-8000-000000000001', '" + EXPORT_ANSWER + "', 3)");
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
}
