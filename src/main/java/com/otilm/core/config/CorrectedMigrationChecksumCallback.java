package com.otilm.core.config;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.Configuration;
import org.springframework.stereotype.Component;

/**
 * Moves the recorded checksum of a migration corrected in place to the corrected script's, so a database that applied
 * the earlier script passes Flyway's validation. Only the exact earlier checksum is accepted, so any other drift still
 * fails validation.
 */
@Component
public class CorrectedMigrationChecksumCallback implements Callback {

    static final List<CorrectedMigration> CORRECTED_MIGRATIONS = List
            .of(new CorrectedMigration("202611051000", 830573980, 618419275));

    private final List<CorrectedMigration> correctedMigrations;

    public CorrectedMigrationChecksumCallback() {
        this(CORRECTED_MIGRATIONS);
    }

    CorrectedMigrationChecksumCallback(List<CorrectedMigration> correctedMigrations) {
        this.correctedMigrations = correctedMigrations;
    }

    @Override
    public boolean supports(Event event, Context context) {
        return event == Event.BEFORE_VALIDATE;
    }

    @Override
    public boolean canHandleInTransaction(Event event, Context context) {
        return true;
    }

    @Override
    public void handle(Event event, Context context) {
        Configuration configuration = context.getConfiguration();
        String schema = FlywaySearchPathCallback.defaultSchema(configuration);
        if (schema == null) {
            return;
        }
        String history = FlywaySearchPathCallback.quoteIdentifier(schema) + "."
                + FlywaySearchPathCallback.quoteIdentifier(configuration.getTable());
        Connection connection = context.getConnection();
        try {
            if (!exists(connection, history)) {
                return;
            }
            try (PreparedStatement statement = connection
                    .prepareStatement("UPDATE " + history + " SET checksum = ? WHERE version = ? AND checksum = ?")) {
                for (CorrectedMigration migration : correctedMigrations) {
                    statement.setInt(1, migration.correctedChecksum());
                    statement.setString(2, migration.version());
                    statement.setInt(3, migration.appliedChecksum());
                    statement.executeUpdate();
                }
            }
        } catch (SQLException e) {
            throw new FlywayException("Failed to accept corrected migration checksums in " + history, e);
        }
    }

    @Override
    public String getCallbackName() {
        return getClass().getSimpleName();
    }

    private static boolean exists(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, table);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() && resultSet.getBoolean(1);
            }
        }
    }

    /** A migration's checksum as some databases applied it, and the checksum of the script that corrected it. */
    record CorrectedMigration(String version, int appliedChecksum, int correctedChecksum) {
    }
}
