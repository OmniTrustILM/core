package com.otilm.core.config;

import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.Configuration;
import org.springframework.stereotype.Component;

/**
 * Pins {@code search_path} to the Flyway default schema inside each migration's own transaction.
 * <p>
 * Behind PgBouncer in transaction pool mode, session state does not follow the client connection: the pool's
 * session-level {@code search_path} lands on whichever server connection served it, and a migration transaction may run
 * on another one. Flyway sets the search path itself only when its one-time {@code SHOW search_path} does not already
 * report the schema, so a migration referencing tables unqualified could fail with "relation does not exist".
 * {@code SET LOCAL} is scoped to the transaction, which PgBouncer keeps on one server connection. A migration that runs
 * outside a transaction gets no such pinning and must schema-qualify its objects.
 */
@Component
public class FlywaySearchPathCallback implements Callback {

    @Override
    public boolean supports(Event event, Context context) {
        return event == Event.BEFORE_EACH_MIGRATE;
    }

    @Override
    public boolean canHandleInTransaction(Event event, Context context) {
        return true;
    }

    @Override
    public void handle(Event event, Context context) {
        String schema = defaultSchema(context.getConfiguration());
        if (schema == null) {
            return;
        }
        try (Statement statement = context.getConnection().createStatement()) {
            statement.execute("SET LOCAL search_path TO " + quoteIdentifier(schema));
        } catch (SQLException e) {
            throw new FlywayException("Failed to set search_path to schema " + schema, e);
        }
    }

    @Override
    public String getCallbackName() {
        return getClass().getSimpleName();
    }

    private static String defaultSchema(Configuration configuration) {
        if (configuration.getDefaultSchema() != null) {
            return configuration.getDefaultSchema();
        }
        String[] schemas = configuration.getSchemas();
        return schemas.length > 0 ? schemas[0] : null;
    }

    private static String quoteIdentifier(String identifier) {
        return '"' + identifier.replace("\"", "\"\"") + '"';
    }
}
