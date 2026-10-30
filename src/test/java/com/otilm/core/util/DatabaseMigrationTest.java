package com.otilm.core.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Simple tests for calculating checksums and validating the migration scripts integrity.
 */
class DatabaseMigrationTest {

    private static final List<String> MIGRATION_DIRECTORIES = List
            .of("src/main/resources/db/migration", "src/main/java/db/migration");

    private static final Pattern MIGRATION_FILE = Pattern.compile("^V(?<version>[^_]+)__.+\\.(sql|java)$");

    @Test
    void testJavaMigrationsChecksums() {
        for (DatabaseMigration.JavaMigrationChecksums migrationChecksum : DatabaseMigration.JavaMigrationChecksums
                .values()) {
            if (migrationChecksum.isAltered()) {
                continue;
            }
            try {
                int checksum = DatabaseMigration
                        .calculateChecksum("src/main/java/db/migration/" + migrationChecksum.name() + ".java");
                Assertions
                        .assertEquals(migrationChecksum.getChecksum(), checksum,
                                "Error in checking checksum of Java migration: " + migrationChecksum.name());
            } catch (IOException e) {
                // not found file, skip checking checksum
            }
        }
    }

    @Test
    void migrationVersionsAreUnique() throws IOException {
        Map<String, List<String>> repeatedVersions = new TreeMap<>(migrationFilesByVersion());
        repeatedVersions.values().removeIf(files -> files.size() == 1);

        assertThat(repeatedVersions)
                .as("Flyway refuses a migration set that assigns one version to several scripts")
                .isEmpty();
    }

    private static Map<String, List<String>> migrationFilesByVersion() throws IOException {
        Map<String, List<String>> filesByVersion = new TreeMap<>();
        for (String directory : MIGRATION_DIRECTORIES) {
            try (Stream<Path> files = Files.list(Path.of(directory))) {
                files
                        .map(file -> MIGRATION_FILE.matcher(file.getFileName().toString()))
                        .filter(Matcher::matches)
                        .forEach(matcher -> filesByVersion
                                .computeIfAbsent(matcher.group("version"), version -> new ArrayList<>())
                                .add(matcher.group()));
            }
        }
        return filesByVersion;
    }
}
