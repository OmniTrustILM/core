package com.otilm.core.integration.migration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Verifies the data repair of {@code V202607211000__notification_profile_version_unique_version.sql}
 * against seeded duplicate version rows. The regular test bootstrap generates the unique constraint
 * from the entity annotation on an empty schema, so without this test the renumbering and the
 * {@code pending_notification} remap would never execute against data.
 */
class NotificationProfileVersionUniqueMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202607211000__notification_profile_version_unique_version.sql";

    private static final String PROFILE_A = "aaaaaaaa-0000-0000-0000-000000000000";
    private static final String PROFILE_B = "bbbbbbbb-0000-0000-0000-000000000000";

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

            // Profile A had versions [1, 2, 2, 2, 3]; duplicates are renumbered densely by creation time.
            Map<String, Integer> profileAVersions = versionsByUuid(connection, PROFILE_A);
            Assertions.assertEquals(1, profileAVersions.get("a0000000-0000-0000-0000-000000000001"));
            Assertions.assertEquals(2, profileAVersions.get("a0000000-0000-0000-0000-000000000002"));
            Assertions.assertEquals(3, profileAVersions.get("a0000000-0000-0000-0000-000000000005"));
            Assertions.assertEquals(4, profileAVersions.get("a0000000-0000-0000-0000-000000000003"));
            Assertions.assertEquals(5, profileAVersions.get("a0000000-0000-0000-0000-000000000004"));

            // Profile B had no duplicates and must be untouched.
            Map<String, Integer> profileBVersions = versionsByUuid(connection, PROFILE_B);
            Assertions.assertEquals(1, profileBVersions.get("b0000000-0000-0000-0000-000000000001"));
            Assertions.assertEquals(2, profileBVersions.get("b0000000-0000-0000-0000-000000000002"));

            // Pending references follow the renumbering: an unambiguous version follows its row, an
            // ambiguous (duplicated) version maps to the latest-created duplicate, clean profiles stay.
            Assertions.assertEquals(5, pendingVersion(connection, "e0000000-0000-0000-0000-000000000001"));
            Assertions.assertEquals(4, pendingVersion(connection, "e0000000-0000-0000-0000-000000000002"));
            Assertions.assertEquals(1, pendingVersion(connection, "e0000000-0000-0000-0000-000000000003"));
            Assertions.assertEquals(2, pendingVersion(connection, "e0000000-0000-0000-0000-000000000004"));

            // The unique constraint is in place again and rejects duplicates.
            try (Statement statement = connection.createStatement()) {
                SQLException rejection = Assertions.assertThrows(SQLException.class, () -> statement.execute("""
                        INSERT INTO notification_profile_version
                            (uuid, notification_profile_uuid, version, recipient_type, internal_notification, created_at)
                        VALUES ('c0000000-0000-0000-0000-000000000001', '%s', 1, 'OWNER', true, now())
                        """.formatted(PROFILE_A)));
                Assertions.assertTrue(rejection.getMessage().contains("uq_notification_profile_version"),
                        "Duplicate insert should be rejected by the unique constraint, but was: " + rejection.getMessage());
            }
        }
    }

    private void seedPreMigrationState(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // The entity-generated schema already carries the constraint; drop it to seed pre-migration data.
            statement.execute("ALTER TABLE notification_profile_version DROP CONSTRAINT uq_notification_profile_version");

            statement.execute("""
                    INSERT INTO notification_profile (uuid, name, version_lock, created_at) VALUES
                        ('%s', 'ProfileWithDuplicates', 0, now()),
                        ('%s', 'CleanProfile', 0, now())
                    """.formatted(PROFILE_A, PROFILE_B));

            statement.execute("""
                    INSERT INTO notification_profile_version
                        (uuid, notification_profile_uuid, version, recipient_type, internal_notification, created_at)
                    VALUES
                        ('a0000000-0000-0000-0000-000000000001', '%1$s', 1, 'OWNER', true, TIMESTAMP '2026-01-01 10:00:00'),
                        ('a0000000-0000-0000-0000-000000000002', '%1$s', 2, 'OWNER', true, TIMESTAMP '2026-01-02 10:00:00'),
                        ('a0000000-0000-0000-0000-000000000003', '%1$s', 2, 'OWNER', true, TIMESTAMP '2026-01-02 10:05:00'),
                        ('a0000000-0000-0000-0000-000000000005', '%1$s', 2, 'OWNER', true, TIMESTAMP '2026-01-02 10:02:00'),
                        ('a0000000-0000-0000-0000-000000000004', '%1$s', 3, 'OWNER', true, TIMESTAMP '2026-01-03 10:00:00'),
                        ('b0000000-0000-0000-0000-000000000001', '%2$s', 1, 'OWNER', true, TIMESTAMP '2026-01-01 10:00:00'),
                        ('b0000000-0000-0000-0000-000000000002', '%2$s', 2, 'OWNER', true, TIMESTAMP '2026-01-02 10:00:00')
                    """.formatted(PROFILE_A, PROFILE_B));

            statement.execute("""
                    INSERT INTO pending_notification
                        (uuid, resource, object_uuid, notification_profile_uuid, version, last_sent_at, repetitions)
                    VALUES
                        ('e0000000-0000-0000-0000-000000000001', 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000001', '%1$s', 3, now(), 0),
                        ('e0000000-0000-0000-0000-000000000002', 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000002', '%1$s', 2, now(), 0),
                        ('e0000000-0000-0000-0000-000000000003', 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000003', '%1$s', 1, now(), 0),
                        ('e0000000-0000-0000-0000-000000000004', 'CERTIFICATE', 'd0000000-0000-0000-0000-000000000004', '%2$s', 2, now(), 0)
                    """.formatted(PROFILE_A, PROFILE_B));
        }
    }

    private Map<String, Integer> versionsByUuid(Connection connection, String profileUuid) throws SQLException {
        Map<String, Integer> versions = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT uuid, version FROM notification_profile_version WHERE notification_profile_uuid = '%s' ORDER BY version".formatted(profileUuid))) {
            while (resultSet.next()) {
                versions.put(resultSet.getString("uuid"), resultSet.getInt("version"));
            }
        }
        return versions;
    }

    private int pendingVersion(Connection connection, String pendingUuid) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT version FROM pending_notification WHERE uuid = '%s'".formatted(pendingUuid))) {
            Assertions.assertTrue(resultSet.next(), "pending_notification row " + pendingUuid + " should exist");
            return resultSet.getInt("version");
        }
    }
}
