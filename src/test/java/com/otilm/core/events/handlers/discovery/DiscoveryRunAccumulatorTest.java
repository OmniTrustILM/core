package com.otilm.core.events.handlers.discovery;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryRunAccumulatorTest {

    private static final Long CONTENT_A = 1L;
    private static final Long CONTENT_B = 2L;

    private final UUID rowA = UUID.randomUUID();
    private final UUID rowB = UUID.randomUUID();
    private final UUID certA = UUID.randomUUID();

    @Test
    void countsNothingForACleanRun() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator.accept(committedGroup(imported(rowA), ignored(rowB)));

        assertThat(accumulator.counts()).isEqualTo(new DiscoveryRunCounts(0, 0, 0, 0, false));
        assertThat(accumulator.counts().allClear()).isTrue();
    }

    @Test
    void countsARolledBackGroupOncePerCertificateNotPerRow() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A, List.of(rolledBack(rowA), rolledBack(rowB)), List.of(),
                        false));

        assertThat(accumulator.counts().inventoryGaps())
                .as("one certificate on two hosts is one certificate")
                .isEqualTo(1);
        assertThat(accumulator.results()).hasSize(2);
    }

    @Test
    void countsDistinctFailedGroupsSeparately() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator.accept(new GroupImportResult(CONTENT_A, List.of(rolledBack(rowA)), List.of(), false));
        accumulator.accept(new GroupImportResult(CONTENT_B, List.of(entityCreationFailed(rowB)), List.of(), false));

        assertThat(accumulator.counts().inventoryGaps()).isEqualTo(2);
    }

    @Test
    void reclassifiesImportedToKeyAssociationFailed() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A, List.of(imported(rowA), imported(rowB)),
                        List.of(KeyQueueEntry.of(null, false, certA, List.of(rowA, rowB))), true));

        accumulator.failKeyAssociation(certA, "the cryptographic key service rejected the key");

        assertThat(accumulator.results())
                .allSatisfy(result -> assertThat(result.outcome())
                        .isEqualTo(DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED));
        assertThat(accumulator.counts().keyGaps()).isEqualTo(1);
        assertThat(accumulator.counts().inventoryGaps()).isZero();
    }

    @Test
    void aggregatesBothKeyFailuresOfOneCertificateIntoOneReason() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A, List.of(imported(rowA)),
                        List.of(KeyQueueEntry.of(null, false, certA, List.of(rowA))), true));

        accumulator.failKeyAssociation(certA, "primary key failed");
        accumulator.failKeyAssociation(certA, "alternative key failed");

        assertThat(accumulator.counts().keyGaps())
                .as("one certificate, one gap, however many of its keys failed")
                .isEqualTo(1);
        assertThat(accumulator.results())
                .singleElement()
                .satisfies(result -> assertThat(result.detail())
                        .contains("primary key failed")
                        .contains("alternative key failed"));
    }

    @Test
    void aRolledBackGroupCannotAlsoBecomeAKeyGap() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator.accept(new GroupImportResult(CONTENT_A, List.of(rolledBack(rowA)), List.of(), false));

        accumulator.failKeyAssociation(certA, "should not apply");

        assertThat(accumulator.counts().inventoryGaps()).isEqualTo(1);
        assertThat(accumulator.counts().keyGaps()).isZero();
        assertThat(accumulator.results()).singleElement().satisfies(result -> {
            assertThat(result.outcome()).isEqualTo(DiscoveryCertificateOutcome.IMPORT_ROLLED_BACK);
            assertThat(result.detail()).startsWith("Import rolled back:");
        });
    }

    @Test
    void ignoresKeyEntriesFromAGroupThatDidNotCommit() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A, List.of(rolledBack(rowA)),
                        List.of(KeyQueueEntry.of(null, false, certA, List.of(rowA))), false));

        accumulator.failKeyAssociation(certA, "the key was queued by a transaction that rolled back");

        assertThat(accumulator.counts().keyGaps())
                .as("an uncommitted group must not register its rows for later re-classification")
                .isZero();
    }

    @Test
    void countsNotAttemptedAndBookkeepingFailuresSeparately() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A,
                        List
                                .of(new DiscoveryCertificateResult(rowA, DiscoveryCertificateOutcome.NOT_ATTEMPTED,
                                        "the import was interrupted before it began")),
                        List.of(), false));
        accumulator.recordBookkeepingFailure();

        DiscoveryRunCounts counts = accumulator.counts();
        assertThat(counts.notAttempted()).isEqualTo(1);
        assertThat(counts.bookkeepingFailures()).isEqualTo(1);
        assertThat(counts.inventoryGaps()).as("never attempted is not the same as lost").isZero();
        assertThat(counts.allClear()).isFalse();
    }

    @Test
    void countsAnUnattemptedGroupOncePerCertificateNotPerRow() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        accumulator
                .accept(new GroupImportResult(CONTENT_A, List.of(notAttempted(rowA), notAttempted(rowB)), List.of(),
                        false));

        assertThat(accumulator.counts().notAttempted())
                .as("the status message says certificate(s) for this count too, so rows would make it lie")
                .isEqualTo(1);
        assertThat(accumulator.results()).hasSize(2);
    }

    private GroupImportResult committedGroup(DiscoveryCertificateResult... rows) {
        return new GroupImportResult(CONTENT_A, List.of(rows), List.of(), true);
    }

    private DiscoveryCertificateResult imported(UUID row) {
        return new DiscoveryCertificateResult(row, DiscoveryCertificateOutcome.IMPORTED, null);
    }

    private DiscoveryCertificateResult ignored(UUID row) {
        return new DiscoveryCertificateResult(row, DiscoveryCertificateOutcome.IGNORED, null);
    }

    private DiscoveryCertificateResult rolledBack(UUID row) {
        return new DiscoveryCertificateResult(row, DiscoveryCertificateOutcome.IMPORT_ROLLED_BACK,
                "Import rolled back: database constraint violation");
    }

    private DiscoveryCertificateResult notAttempted(UUID row) {
        return new DiscoveryCertificateResult(row, DiscoveryCertificateOutcome.NOT_ATTEMPTED,
                "the import did not run to a result");
    }

    private DiscoveryCertificateResult entityCreationFailed(UUID row) {
        return new DiscoveryCertificateResult(row, DiscoveryCertificateOutcome.ENTITY_CREATION_FAILED,
                "Unable to create certificate entity: the content could not be parsed");
    }
}
