package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the certificate import entry migrations as Flyway will. The test bootstrap generates its schema from the
 * entities, and no entity maps the table any more, so this is where its removal is proven.
 */
class CertificateImportEntryMigrationITest extends BaseSpringBootTest {

    private static final String CREATE_RESOURCE = "db/migration/V202609271200__certificate_import_entry.sql";

    private static final String DROP_RESOURCE = "db/migration/V202609291000__drop_certificate_import_entry.sql";

    private static final String SCRATCH_SCHEMA = "certificate_import_entry_migration_check";

    private static final String TABLE_COUNT = """
            SELECT count(*) FROM information_schema.tables
            WHERE table_schema = ? AND table_name = 'certificate_import_entry'
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void theTableIsDropped() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                createScratchSchema(connection);
                runMigration(connection, CREATE_RESOURCE);
                assertThat(tableExists(connection)).isTrue();

                // when
                runMigration(connection, DROP_RESOURCE);

                // then
                assertThat(tableExists(connection)).isFalse();
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private static void createScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
        }
    }

    private static void runMigration(Connection connection, String resource) throws Exception {
        String migration = new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private static boolean tableExists(Connection connection) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement(TABLE_COUNT)) {
            query.setString(1, SCRATCH_SCHEMA);
            try (ResultSet count = query.executeQuery()) {
                count.next();
                return count.getLong(1) == 1;
            }
        }
    }

    private static void dropScratchSchema(Connection connection) throws SQLException {
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
