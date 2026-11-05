package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the migration that gives ACME profiles the documented defaults in a scratch schema holding the two columns as
 * {@code V202201311030__acme.sql} created them.
 */
class AcmeProfileDocumentedDefaultsMigrationITest extends BaseSpringBootTest {

    private static final String SCRATCH_SCHEMA = "acme_profile_defaults_migration_check";

    private static final String MIGRATION = "db/migration/V202611052030__acme_profile_documented_defaults.sql";

    private static final String ACME_PROFILE_TABLE = """
            CREATE TABLE acme_profile (
                name VARCHAR PRIMARY KEY,
                validity BIGINT NULL DEFAULT NULL,
                retry_interval BIGINT NULL DEFAULT NULL
            );
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void givesDocumentedDefaults_whenProfileHoldsExactlyTheSwappedPair() throws Exception {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            try {
                // given
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(ACME_PROFILE_TABLE);
                statement.execute("""
                        INSERT INTO acme_profile VALUES ('swapped defaults', 30, 36000);
                        INSERT INTO acme_profile VALUES ('short validity, short retry', 30, 60);
                        INSERT INTO acme_profile VALUES ('long validity, long retry', 3600, 36000);
                        INSERT INTO acme_profile VALUES ('nothing set', NULL, NULL);
                        """);
                String migration = new ClassPathResource(MIGRATION).getContentAsString(StandardCharsets.UTF_8);

                // when
                statement.execute(migration);

                // then
                assertThat(readProfiles(statement))
                        .containsExactly("long validity, long retry: 3600/36000", "nothing set: null/null",
                                "short validity, short retry: 30/60", "swapped defaults: 36000/30");
            } finally {
                // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                // must not point at the schema this drops.
                statement.execute("RESET search_path");
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Each profile as {@code name: validity/retry_interval}, ordered by name. */
    private static List<String> readProfiles(Statement statement) throws Exception {
        List<String> profiles = new ArrayList<>();
        try (ResultSet rows = statement
                .executeQuery("SELECT name, validity, retry_interval FROM acme_profile ORDER BY name")) {
            while (rows.next()) {
                profiles.add(rows.getString(1) + ": " + rows.getString(2) + "/" + rows.getString(3));
            }
        }
        return profiles;
    }
}
