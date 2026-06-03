package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRecordOutboxRepositoryTest extends BaseSpringBootTest {

    private static final int BATCH_LARGER_THAN_FIXTURES = 1000;
    private static final int POISON_THRESHOLD = 10;

    @Autowired
    private SigningRecordOutboxRepository repository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    /**
     * Wraps the {@code @Modifying} {@code recordFailure} query, which requires an active transaction. Fixtures are
     * committed outside it, mirroring the drainer running the update over already-persisted, claimed rows.
     */
    private TransactionTemplate transactionTemplate;

    @BeforeEach
    void initTransactionTemplate() {
        transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Test
    void findDrainableBatch_returnsRowsOrderedBySigningTimeOldestFirst() {
        // given
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        var oldest = now.minus(Duration.ofHours(2));
        var middle = now.minus(Duration.ofHours(1));
        var newest = now;
        insertOutbox(middle);
        insertOutbox(newest);
        insertOutbox(oldest);

        // when
        List<SigningRecordOutbox> drainable = repository.findDrainableBatch(POISON_THRESHOLD, BATCH_LARGER_THAN_FIXTURES);

        // then
        assertEquals(List.of(oldest, middle, newest),
                drainable.stream().map(SigningRecordOutbox::getSigningTime).toList());
    }

    @Test
    void findDrainableBatch_limitsResultToBatchSize() {
        // given
        var batchSize = 2;
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        var oldest = now.minus(Duration.ofHours(2));
        var middle = now.minus(Duration.ofHours(1));
        var newest = now;
        insertOutbox(oldest);
        insertOutbox(middle);
        insertOutbox(newest);

        // when
        List<SigningRecordOutbox> drainable = repository.findDrainableBatch(POISON_THRESHOLD, batchSize);

        // then
        assertEquals(List.of(oldest, middle),
                drainable.stream().map(SigningRecordOutbox::getSigningTime).toList());
    }

    @Test
    void findDrainableBatch_excludesPoisonedRows() {
        // given
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        var drainable = now.minus(Duration.ofHours(1));
        insertOutbox(now.minus(Duration.ofHours(3)), POISON_THRESHOLD);       // poisoned, oldest
        insertOutbox(now.minus(Duration.ofHours(2)), POISON_THRESHOLD + 1);   // poisoned, older
        insertOutbox(drainable, POISON_THRESHOLD - 1);                        // still drainable

        // when
        List<SigningRecordOutbox> found = repository.findDrainableBatch(POISON_THRESHOLD, BATCH_LARGER_THAN_FIXTURES);

        // then only the below-threshold row is returned, even though poisoned rows are older
        assertEquals(List.of(drainable), found.stream().map(SigningRecordOutbox::getSigningTime).toList());
    }

    @Test
    void findDrainableBatch_returnsEmptyWhenOutboxEmpty() {
        // given
        // no outbox rows

        // when
        List<SigningRecordOutbox> drainable = repository.findDrainableBatch(POISON_THRESHOLD, BATCH_LARGER_THAN_FIXTURES);

        // then
        assertTrue(drainable.isEmpty());
    }

    @Test
    void findOldestSigningTimeBelowPoisonThreshold_returnsEarliestDrainableSigningTime() {
        // given
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        var oldestDrainable = now.minus(Duration.ofHours(2));
        var poisonedButOlder = now.minus(Duration.ofHours(3));
        insertOutbox(poisonedButOlder, POISON_THRESHOLD);
        insertOutbox(now.minus(Duration.ofHours(1)));
        insertOutbox(oldestDrainable);

        // when
        Optional<Instant> found = repository.findOldestSigningTimeBelowPoisonThreshold(POISON_THRESHOLD);

        // then
        assertEquals(Optional.of(oldestDrainable), found);
    }

    @Test
    void findOldestSigningTimeBelowPoisonThreshold_returnsEmptyWhenAllRowsPoisoned() {
        // given
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        insertOutbox(now, POISON_THRESHOLD);
        insertOutbox(now.minus(Duration.ofHours(1)), POISON_THRESHOLD + 1);

        // when
        Optional<Instant> found = repository.findOldestSigningTimeBelowPoisonThreshold(POISON_THRESHOLD);

        // then
        assertTrue(found.isEmpty());
    }

    @Test
    void countPoisoned_countsOnlyRowsAtOrAboveThreshold() {
        // given
        var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        insertOutbox(now, POISON_THRESHOLD - 1);
        insertOutbox(now, POISON_THRESHOLD);
        insertOutbox(now, POISON_THRESHOLD + 1);

        // when
        long poisoned = repository.countPoisoned(POISON_THRESHOLD);

        // then
        assertEquals(2, poisoned);
    }

    @Test
    void recordFailure_incrementsAttemptsAndSetsLastError() {
        // given
        var failureMessage = "connector timed out";
        SigningRecordOutbox row = insertOutbox();

        // when
        doInTransaction(() -> repository.recordFailure(List.of(row.getUuid()), failureMessage));

        // then
        SigningRecordOutbox reloaded = repository.findById(row.getUuid()).orElseThrow();
        assertEquals(1, reloaded.getAttempts());
        assertEquals(failureMessage, reloaded.getLastError());
    }

    @Test
    void recordFailure_onlyAffectsGivenUuids() {
        // given
        var failureMessage = "connector timed out";
        SigningRecordOutbox failed = insertOutbox();
        SigningRecordOutbox untouched = insertOutbox();

        // when
        doInTransaction(() -> repository.recordFailure(List.of(failed.getUuid()), failureMessage));

        // then
        SigningRecordOutbox reloaded = repository.findById(untouched.getUuid()).orElseThrow();
        assertEquals(0, reloaded.getAttempts());
        assertNull(reloaded.getLastError());
    }

    private void doInTransaction(Runnable modifyingQuery) {
        transactionTemplate.executeWithoutResult(status -> modifyingQuery.run());
    }

    private SigningRecordOutbox insertOutbox() {
        return insertOutbox(Instant.now().truncatedTo(ChronoUnit.MICROS));
    }

    private SigningRecordOutbox insertOutbox(Instant signingTime) {
        var noAttemptsYet = 0;
        return insertOutbox(signingTime, noAttemptsYet);
    }

    private SigningRecordOutbox insertOutbox(Instant signingTime, int attempts) {
        var anyProfileVersion = 1;
        SigningRecordOutbox outbox = new SigningRecordOutbox();
        outbox.setUuid(UUID.randomUUID());
        outbox.setSigningProfileVersion(anyProfileVersion);
        outbox.setSigningTime(signingTime);
        outbox.setAttempts(attempts);
        return repository.saveAndFlush(outbox);
    }
}
