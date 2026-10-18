package com.otilm.core.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.ClassicConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Runs Flyway, wired by Spring Boot as in production, through PgBouncer in transaction pool mode (the Helm chart
 * default) with the pool pinning the schema the way {@code spring.datasource.hikari.schema} does.
 */
@Testcontainers
class FlywaySearchPathCallbackTest {

    private static final String SCHEMA = "core";
    private static final Network NETWORK = Network.newNetwork();

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine")
            .withNetwork(NETWORK)
            .withNetworkAliases("postgres");

    @Container
    private static final GenericContainer<?> PGBOUNCER = new GenericContainer<>("edoburu/pgbouncer:v1.24.1-p1")
            .withNetwork(NETWORK)
            .withEnv("DB_HOST", "postgres")
            .withEnv("DB_USER", POSTGRES.getUsername())
            .withEnv("DB_PASSWORD", POSTGRES.getPassword())
            .withEnv("AUTH_TYPE", "plain")
            .withEnv("POOL_MODE", "transaction")
            .withEnv("MAX_PREPARED_STATEMENTS", "10")
            .withExposedPorts(5432)
            .dependsOn(POSTGRES);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class));

    @Test
    void migrationReferencingTablesUnqualified_failsBehindPgBouncer_withoutCallback() throws SQLException {
        // given
        String database = databaseWithWidget();

        // when
        runner.withPropertyValues(properties(database)).run(context -> {
            // then
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("relation \"widget\" does not exist");
        });
    }

    @Test
    void migrationReferencingTablesUnqualified_succeedsBehindPgBouncer_withCallback() throws SQLException {
        // given
        String database = databaseWithWidget();

        // when
        runner.withPropertyValues(properties(database)).withBean(FlywaySearchPathCallback.class).run(context -> {
            // then
            assertThat(context).hasNotFailed();
            assertThat(widgetName(database)).isEqualTo("migrated");
        });
    }

    @Test
    void handle_pinsDefaultSchema_overFirstOfSchemas() throws SQLException {
        // given
        ClassicConfiguration configuration = new ClassicConfiguration();
        configuration.setSchemas(new String[]{"core", "audit"});
        configuration.setDefaultSchema("audit");
        Statement statement = mock(Statement.class);

        // when
        new FlywaySearchPathCallback().handle(Event.BEFORE_EACH_MIGRATE, context(configuration, statement));

        // then
        verify(statement).execute("SET LOCAL search_path TO \"audit\"");
    }

    @Test
    void handle_quotesSchemaAsIdentifier() throws SQLException {
        // given
        ClassicConfiguration configuration = new ClassicConfiguration();
        configuration.setSchemas(new String[]{"we\"ird"});
        Statement statement = mock(Statement.class);

        // when
        new FlywaySearchPathCallback().handle(Event.BEFORE_EACH_MIGRATE, context(configuration, statement));

        // then
        verify(statement).execute("SET LOCAL search_path TO \"we\"\"ird\"");
    }

    @Test
    void handle_leavesSearchPathAlone_whenNoSchemaConfigured() throws SQLException {
        // given
        Statement statement = mock(Statement.class);

        // when
        new FlywaySearchPathCallback()
                .handle(Event.BEFORE_EACH_MIGRATE, context(new ClassicConfiguration(), statement));

        // then
        verifyNoInteractions(statement);
    }

    private static Context context(ClassicConfiguration configuration, Statement statement) throws SQLException {
        Connection connection = mock(Connection.class);
        when(connection.createStatement()).thenReturn(statement);
        Context context = mock(Context.class);
        when(context.getConfiguration()).thenReturn(configuration);
        when(context.getConnection()).thenReturn(connection);
        return context;
    }

    // A fresh database per test gives each its own PgBouncer pool, so no server connection carries a search_path
    // left behind by another test.
    private static String databaseWithWidget() throws SQLException {
        String database = "db_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection connection = directConnection(POSTGRES.getDatabaseName());
                Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE " + database);
        }
        try (Connection connection = directConnection(database); Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA " + SCHEMA);
            statement.execute("CREATE TABLE " + SCHEMA + ".widget (id INT PRIMARY KEY, name TEXT)");
            statement.execute("INSERT INTO " + SCHEMA + ".widget VALUES (1, 'original')");
        }
        return database;
    }

    private static String[] properties(String database) {
        return new String[]{
                "spring.datasource.url=jdbc:postgresql://" + PGBOUNCER.getHost() + ":" + PGBOUNCER.getMappedPort(5432)
                        + "/" + database,
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword(),
                "spring.datasource.hikari.schema=" + SCHEMA,
                // No background fill: the pool's session-level search_path then lands on a single server connection,
                // which Flyway's lock transaction holds, so the migration transaction always gets one without it.
                "spring.datasource.hikari.minimum-idle=0",
                "spring.flyway.schemas=" + SCHEMA,
                "spring.flyway.baseline-on-migrate=true",
                "spring.flyway.baseline-version=0",
                "spring.flyway.locations=classpath:db/flyway-search-path"};
    }

    private static String widgetName(String database) throws SQLException {
        try (Connection connection = directConnection(database);
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery("SELECT name FROM " + SCHEMA + ".widget WHERE id = 1")) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }

    private static Connection directConnection(String database) throws SQLException {
        String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + database;
        return DriverManager.getConnection(url, POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
