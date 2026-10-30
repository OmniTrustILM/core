package com.otilm.core.integration.migration;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenInstanceConnectorInterfaceMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202608201200__add_connector_interface_to_token_instance.sql";

    @Autowired
    private DataSource dataSource;

    @Test
    void migration_makesLegacyOnlyTokenFieldsNullable_andAddsInterfaceAssociation() throws Exception {
        // given
        try (Connection connection = dataSource.getConnection()) {
            simulateOldTokenInstanceSchema(connection);
            String migrationSql = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);

            // when
            try (Statement statement = connection.createStatement()) {
                statement.execute(migrationSql);
            }

            // then
            assertEquals("YES", columnProperty(connection, "kind", "is_nullable"));
            assertEquals("YES", columnProperty(connection, "token_instance_uuid", "is_nullable"));
            assertEquals("YES", columnProperty(connection, "connector_interface_uuid", "is_nullable"));
        }
    }

    private static void simulateOldTokenInstanceSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE token_instance_reference DROP COLUMN connector_interface_uuid");
            statement.execute("""
                    ALTER TABLE token_instance_reference
                        ALTER COLUMN kind SET NOT NULL,
                        ALTER COLUMN token_instance_uuid SET NOT NULL
                    """);
        }
    }

    private static String columnProperty(Connection connection, String column, String property) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(("""
                SELECT %s FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'token_instance_reference'
                  AND column_name = '%s'
                """).formatted(property, column))) {
            return resultSet.next() ? resultSet.getString(1) : null;
        }
    }
}
