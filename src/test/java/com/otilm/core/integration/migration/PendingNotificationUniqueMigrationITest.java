package com.otilm.core.integration.migration;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

/**
 * Verifies the data repair of {@code V202608031000__pending_notification_unique_suppression_row.sql} against seeded
 * duplicate suppression rows. The regular test bootstrap generates the unique constraint from the entity annotation on
 * an empty schema, so without this test the deduplication would never execute against data, including legacy rows with
 * a NULL event.
 */
class PendingNotificationUniqueMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202608031000__pending_notification_unique_suppression_row.sql";

    private static final String PROFILE = "aaaaaaaa-0000-0000-0000-000000000000";

    @Autowired
    DataSource dataSource;

    @Test
    void testMigration() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            seedPreMigrationState(connection);

            String migrationSql = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
            // Flyway runs the migration in a single transaction; LOCK TABLE requires one, so mirror that here.
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute(migrationSql);
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }

            // Duplicated key (event present): the row with the greatest last_sent_at survives.
            Assertions
                    .assertEquals(List.of("e0000000-0000-0000-0000-000000000002"),
                            rowsForObject(connection, "d0000000-0000-0000-0000-000000000001"));

            // Duplicated key with equal last_sent_at and NULL event: greatest repetitions wins,
            // proving NULL events are matched as duplicates rather than treated as distinct.
            Assertions
                    .assertEquals(List.of("e0000000-0000-0000-0000-000000000012"),
                            rowsForObject(connection, "d0000000-0000-0000-0000-000000000002"));

            // A key without duplicates is untouched.
            Assertions
                    .assertEquals(List.of("e0000000-0000-0000-0000-000000000021"),
                            rowsForObject(connection, "d0000000-0000-0000-0000-000000000003"));

            // The unique constraint is in place and rejects a duplicate suppression row.
            try (Statement statement = connection.createStatement()) {
                SQLException rejection = Assertions
                        .assertThrows(SQLException.class,
                                () -> statement
                                        .execute(
                                                """
                                                        INSERT INTO pending_notification
                                                            (uuid, notification_profile_uuid, version, resource, object_uuid, event, last_sent_at, repetitions)
                                                        VALUES ('c0000000-0000-0000-0000-000000000001', '%s', 1, 'CERTIFICATE',
                                                                'd0000000-0000-0000-0000-000000000001', 'CERTIFICATE_EXPIRING', now(), 0)
                                                        """
                                                        .formatted(PROFILE)));
                Assertions
                        .assertEquals("23505", rejection.getSQLState(),
                                "Duplicate insert should fail with the unique-violation SQLSTATE, but was: "
                                        + rejection.getMessage());
                Assertions
                        .assertTrue(rejection.getMessage().contains("uq_pending_notification_suppression_row"),
                                "Duplicate insert should be rejected by the unique constraint, but was: "
                                        + rejection.getMessage());
            }
        }
    }

    private void seedPreMigrationState(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // The entity-generated schema already carries the constraint; drop it to seed pre-migration data.
            statement
                    .execute(
                            "ALTER TABLE pending_notification DROP CONSTRAINT uq_pending_notification_suppression_row");

            statement.execute("""
                    INSERT INTO notification_profile (uuid, name, version_lock, created_at)
                    VALUES ('%s', 'ProfileWithDuplicates', 0, now())
                    """.formatted(PROFILE));

            statement
                    .execute(
                            """
                                    INSERT INTO pending_notification
                                        (uuid, notification_profile_uuid, version, resource, object_uuid, event, last_sent_at, repetitions)
                                    VALUES
                                        ('e0000000-0000-0000-0000-000000000001', '%1$s', 1, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000001', 'CERTIFICATE_EXPIRING', TIMESTAMP '2026-01-01 10:00:00', 4),
                                        ('e0000000-0000-0000-0000-000000000002', '%1$s', 1, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000001', 'CERTIFICATE_EXPIRING', TIMESTAMP '2026-01-02 12:00:00', 1),
                                        ('e0000000-0000-0000-0000-000000000003', '%1$s', 2, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000001', 'CERTIFICATE_EXPIRING', TIMESTAMP '2026-01-01 10:00:00', 9),
                                        ('e0000000-0000-0000-0000-000000000011', '%1$s', 1, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000002', NULL, TIMESTAMP '2026-01-01 10:00:00', 2),
                                        ('e0000000-0000-0000-0000-000000000012', '%1$s', 1, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000002', NULL, TIMESTAMP '2026-01-01 10:00:00', 7),
                                        ('e0000000-0000-0000-0000-000000000021', '%1$s', 1, 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000003', 'CERTIFICATE_EXPIRING', TIMESTAMP '2026-01-01 10:00:00', 0)
                                    """
                                    .formatted(PROFILE));
        }
    }

    private List<String> rowsForObject(Connection connection, String objectUuid) throws SQLException {
        List<String> uuids = new ArrayList<>();
        try (Statement statement = connection.createStatement();
                ResultSet resultSet = statement
                        .executeQuery("SELECT uuid FROM pending_notification WHERE object_uuid = '%s' ORDER BY uuid"
                                .formatted(objectUuid))) {
            while (resultSet.next()) {
                uuids.add(resultSet.getString("uuid"));
            }
        }
        return uuids;
    }
}
