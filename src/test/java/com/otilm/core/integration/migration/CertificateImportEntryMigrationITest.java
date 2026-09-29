package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs the certificate import entry migration as Flyway will. The test bootstrap generates its schema from the
 * entities, which is where {@code CertificateImportEntry} pins the same constraint, so this is where the migration's
 * own SQL is proven.
 */
class CertificateImportEntryMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609271200__certificate_import_entry.sql";

    private static final String SCRATCH_SCHEMA = "certificate_import_entry_migration_check";

    private static final String INSERT_ENTRY = """
            INSERT INTO certificate_import_entry (uuid, requester_uuid, import_id, digest, state, created_at, updated_at)
            VALUES (gen_random_uuid(), ?, 'import-id', 'digest', 'OPEN', now(), now())
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void theTableExistsWithItsUniqueConstraint() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                UUID requesterUuid = UUID.randomUUID();
                insertEntry(connection, requesterUuid);

                // when
                // then
                assertThatThrownBy(() -> insertEntry(connection, requesterUuid))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("uq_certificate_import_entry");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
        }
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private static void insertEntry(Connection connection, UUID requesterUuid) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(INSERT_ENTRY)) {
            insert.setObject(1, requesterUuid);
            insert.executeUpdate();
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
