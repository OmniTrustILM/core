package com.otilm.core.architecture;

import com.otilm.core.util.DatabaseMigration;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the checksums {@link DatabaseMigration.JavaMigrationChecksums} hands to Flyway. A Java migration reports its
 * checksum from that enum, and Flyway compares the value against the one recorded when the migration ran: register a
 * number that does not belong to the file and every deployment that already ran it refuses to start with a validation
 * error.
 * <p>
 * Only the entries not marked {@code isAltered} are checked. That flag records the ones deliberately frozen at an older
 * value - their source has since changed and re-deriving the checksum would be the very breakage above.
 */
class JavaMigrationChecksumTest {

    private static final Path MIGRATION_ROOT = Path.of("src/main/java/db/migration");

    @Test
    void unalteredMigrationsMustRegisterTheChecksumOfTheirSource() throws IOException {
        List<String> mismatches = new ArrayList<>();
        for (DatabaseMigration.JavaMigrationChecksums entry : DatabaseMigration.JavaMigrationChecksums.values()) {
            if (entry.isAltered()) {
                continue;
            }
            Path source = MIGRATION_ROOT.resolve(entry.name() + ".java");
            assertThat(source).describedAs("Migration source for checksum entry %s", entry.name()).exists();

            int computed = DatabaseMigration.calculateChecksum(source.toString());
            if (computed != entry.getChecksum()) {
                mismatches
                        .add("%s: registered %d, source is %d".formatted(entry.name(), entry.getChecksum(), computed));
            }
        }

        assertThat(mismatches).describedAs("""
                Java migrations whose registered checksum does not match their source file. Flyway validates
                the reported checksum against the one stored when the migration ran, so a wrong value stops
                startup. Recompute with DatabaseMigration.calculateChecksum on the migration source, or - if
                the source changed after the migration shipped - mark the entry isAltered to freeze it.""").isEmpty();
    }

    /** A vacuous pass would hide exactly the mistake this guards, so there must be something left to check. */
    @Test
    void atLeastOneMigrationChecksumIsActuallyVerified() {
        long verifiable = 0;
        for (DatabaseMigration.JavaMigrationChecksums entry : DatabaseMigration.JavaMigrationChecksums.values()) {
            if (!entry.isAltered() && Files.exists(MIGRATION_ROOT.resolve(entry.name() + ".java"))) {
                verifiable++;
            }
        }

        assertThat(verifiable).isPositive();
    }
}
