package com.otilm.core.util;

import java.time.Instant;
import java.util.Date;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationInfoService;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SchemaHistoryTest {

    private static final Instant INSTALLED = Instant.parse("2026-10-05T08:00:00Z");

    @Test
    void readsTheInstallTimeOfTheRequestedVersionOnly() {
        MigrationInfo[] applied = {
                migration("202601271114", Instant.parse("2026-02-01T08:00:00Z")),
                migration("202608271000", INSTALLED)};

        assertThat(SchemaHistory.installedOn(applied, MigrationVersion.fromVersion("202608271000")))
                .contains(INSTALLED);
    }

    @Test
    void aMigrationNotAppliedHasNoInstallTime() {
        MigrationInfo[] applied = {migration("202601271114", INSTALLED)};

        assertThat(SchemaHistory.installedOn(applied, MigrationVersion.fromVersion("202608271000"))).isEmpty();
    }

    @Test
    void readsTheAppliedMigrationsFromFlyway() {
        MigrationInfo[] applied = {migration("202608271000", INSTALLED)};
        MigrationInfoService info = mock(MigrationInfoService.class);
        when(info.applied()).thenReturn(applied);
        Flyway flyway = mock(Flyway.class);
        when(flyway.info()).thenReturn(info);

        assertThat(new SchemaHistory(provider(flyway)).installedOn("202608271000")).contains(INSTALLED);
    }

    @Test
    void withoutFlywayNothingIsInstalled() {
        assertThat(new SchemaHistory(provider(null)).installedOn("202608271000")).isEmpty();
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<Flyway> provider(Flyway flyway) {
        ObjectProvider<Flyway> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(flyway);
        return provider;
    }

    private static MigrationInfo migration(String version, Instant installedOn) {
        MigrationInfo migration = mock(MigrationInfo.class);
        when(migration.getVersion()).thenReturn(MigrationVersion.fromVersion(version));
        when(migration.getInstalledOn()).thenReturn(Date.from(installedOn));
        return migration;
    }
}
