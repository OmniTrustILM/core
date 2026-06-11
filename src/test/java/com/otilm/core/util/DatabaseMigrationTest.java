package com.otilm.core.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * Simple tests for calculating checksums and validating the migration scripts integrity.
 */
class DatabaseMigrationTest {

    @Test
    void testJavaMigrationsChecksums() {
        for (DatabaseMigration.JavaMigrationChecksums migrationChecksum : DatabaseMigration.JavaMigrationChecksums.values()) {
            if(migrationChecksum.isAltered()) {
                continue;
            }
            try {
                int checksum = DatabaseMigration.calculateChecksum("src/main/java/db/migration/" + migrationChecksum.name() + ".java");
                Assertions.assertEquals(migrationChecksum.getChecksum(), checksum, "Error in checking checksum of Java migration: " + migrationChecksum.name());
            } catch (IOException e) {
                // not found file, skip checking checksum
            }
        }
    }
}
