package com.otilm.core.util;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationVersion;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/** Reads Flyway's record of which migrations this database has applied, and when. */
@Component
public class SchemaHistory {

    private final ObjectProvider<Flyway> flyway;

    public SchemaHistory(ObjectProvider<Flyway> flyway) {
        this.flyway = flyway;
    }

    /** Empty where the migration was never applied, or where Flyway does not run (the test schema). */
    public Optional<Instant> installedOn(String version) {
        final Flyway migrations = flyway.getIfAvailable();
        if (migrations == null) {
            return Optional.empty();
        }
        return installedOn(migrations.info().applied(), MigrationVersion.fromVersion(version));
    }

    static Optional<Instant> installedOn(MigrationInfo[] applied, MigrationVersion version) {
        return Arrays
                .stream(applied)
                .filter(migration -> version.equals(migration.getVersion()) && migration.getInstalledOn() != null)
                .map(migration -> migration.getInstalledOn().toInstant())
                .findFirst();
    }
}
