package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202611031200__signing_profile_ilm_native.sql} as Flyway will, in a scratch schema holding a stub of the
 * table it alters, because the regular test bootstrap generates its schema from the entities and nothing else executes
 * this file.
 */
class SigningProfileIlmNativeMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611031200__signing_profile_ilm_native.sql";
    private static final String SCRATCH_SCHEMA = "signing_profile_ilm_native_migration_check";
    private static final String TABLE_STUB = """
            CREATE TABLE "signing_profile" (
                "uuid" UUID PRIMARY KEY,
                "name" TEXT NOT NULL
            )
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void addsNonNullIlmNativeFlagSetToFalse_whenProfilesAlreadyExist() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                // given
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUB);
                statement
                        .execute(
                                "INSERT INTO \"signing_profile\" (\"uuid\", \"name\") VALUES (gen_random_uuid(), 'existing')");
                String migration = new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                        StandardCharsets.UTF_8);

                // when
                statement.execute(migration);

                // then
                try (ResultSet row = statement.executeQuery("SELECT \"ilm_native_enabled\" FROM \"signing_profile\"")) {
                    assertThat(row.next()).isTrue();
                    assertThat(row.getBoolean(1)).isFalse();
                    assertThat(row.next()).isFalse();
                }
                try (ResultSet column = statement
                        .executeQuery("SELECT is_nullable FROM information_schema.columns WHERE table_schema = '"
                                + SCRATCH_SCHEMA
                                + "' AND table_name = 'signing_profile' AND column_name = 'ilm_native_enabled'")) {
                    assertThat(column.next()).isTrue();
                    assertThat(column.getString(1)).isEqualTo("NO");
                }
            } finally {
                try (Statement cleanup = connection.createStatement()) {
                    // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                    // must not point at the schema this drops.
                    cleanup.execute("RESET search_path");
                    cleanup.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                }
            }
        }
    }
}
