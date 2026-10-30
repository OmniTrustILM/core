package com.otilm.core.util;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.sql.DataSource;

/**
 * Empties the test schema between test methods, clearing only the tables that hold rows.
 *
 * <p>
 * Uses {@code DELETE} rather than {@code TRUNCATE} because truncating costs a fresh relfilenode per named table even
 * when that table is already empty. The table list is read from the catalog on every call, and the function itself
 * lives in {@code public}, because {@code BaseMigrationTest} drops and recreates the schema mid-run.
 *
 * <p>
 * Requires a superuser connection. Tables are emptied in catalog order, so foreign-key enforcement is switched off for
 * the duration of the call ({@code session_replication_role = replica}) instead of deriving a dependency order. Against
 * a database where the test user is not superuser every call fails with SQLState 42501; Testcontainers' {@code test}
 * user is superuser, which is the path this class is used on.
 */
public final class TestDatabaseCleaner {

    private static final String UNDEFINED_FUNCTION_SQL_STATE = "42883";

    /** Names outside this cannot be safely interpolated into DDL. */
    private static final Pattern SCHEMA_NAME = Pattern.compile("^[a-zA-Z0-9_]+$");

    /** Stand-in key for the install cache; {@link java.sql.DatabaseMetaData#getURL()} may return null. */
    private static final String UNKNOWN_URL = "unknown";

    private static final String CLEAR_FUNCTION = """
            CREATE OR REPLACE FUNCTION public.otilm_clear_test_schema(target_schema text) RETURNS integer AS $fn$
            DECLARE
                relation text;
                populated boolean;
                cleared integer := 0;
            BEGIN
                -- A schema that does not exist matches no tables, which would silently skip clearing.
                IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = target_schema) THEN
                    RAISE EXCEPTION 'schema % does not exist', target_schema;
                END IF;

                -- Tables are emptied in catalog order rather than dependency order, so disable constraint
                -- enforcement instead of deriving an order.
                SET LOCAL session_replication_role = replica;

                FOR relation IN
                    SELECT c.oid::regclass::text
                    FROM pg_class c
                    JOIN pg_namespace ns ON ns.oid = c.relnamespace
                    WHERE ns.nspname = target_schema
                      AND c.relkind IN ('r', 'p')
                      AND NOT c.relispartition
                LOOP
                    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s)', relation) INTO populated;
                    IF populated THEN
                        EXECUTE format('DELETE FROM %s', relation);
                        cleared := cleared + 1;
                    END IF;
                END LOOP;

                RETURN cleared;
            END
            $fn$ LANGUAGE plpgsql;
            """;

    private static final String CLEAR_CALL = "SELECT public.otilm_clear_test_schema(?)";

    private static final Set<String> INSTALLED_JDBC_URLS = ConcurrentHashMap.newKeySet();

    private TestDatabaseCleaner() {
    }

    static void clear(DataSource dataSource, String schema) throws SQLException {
        requireValidSchemaName(schema);
        try (Connection connection = dataSource.getConnection()) {
            if (!connection.getAutoCommit()) {
                // SET LOCAL and the DELETEs only take effect if the call commits as its own transaction; a pool
                // configured with auto-commit off would roll them back when it reclaims the connection.
                connection.setAutoCommit(true);
            }
            installOnce(connection);
            try {
                clearSchema(connection, schema);
            } catch (SQLException e) {
                if (!UNDEFINED_FUNCTION_SQL_STATE.equals(e.getSQLState())) {
                    throw e;
                }
                // A recycled container can present a known JDBC URL without the function.
                try {
                    install(connection);
                    clearSchema(connection, schema);
                } catch (SQLException retryFailure) {
                    retryFailure.addSuppressed(e);
                    throw retryFailure;
                }
            }
        }
    }

    /**
     * Rejects a schema name that cannot be safely interpolated into DDL. Shared by every caller that interpolates the
     * schema property, so the validation cannot drift apart between them.
     */
    public static void requireValidSchemaName(String schema) {
        if (schema == null || !SCHEMA_NAME.matcher(schema).matches()) {
            throw new IllegalArgumentException("Invalid schema name: " + schema);
        }
    }

    private static synchronized void installOnce(Connection connection) throws SQLException {
        String url = Objects.requireNonNullElse(connection.getMetaData().getURL(), UNKNOWN_URL);
        if (INSTALLED_JDBC_URLS.contains(url)) {
            return;
        }
        install(connection);
        INSTALLED_JDBC_URLS.add(url);
    }

    private static synchronized void install(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(CLEAR_FUNCTION);
        }
    }

    private static void clearSchema(Connection connection, String schema) throws SQLException {
        try (var statement = connection.prepareStatement(CLEAR_CALL)) {
            statement.setString(1, schema);
            statement.execute();
        }
    }
}
