package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * The single transactional persistence layer for the signing-record subsystem. It is a thin wrapper over
 * {@link SigningRecordRepository} and {@link SigningRecordOutboxRepository}: every {@code @Transactional}
 * boundary for signing records lives here, and nothing else does (the persistence-mode orchestration lives in
 * the {@code SigningRecordStrategy} beans, the drain/sweep loops in their own components).
 */
@Component
public class SigningRecordWriter {

    private static final int MAX_ERROR_LENGTH = 1000;

    private final SigningRecordRepository recordRepository;
    private final SigningRecordOutboxRepository outboxRepository;

    public SigningRecordWriter(SigningRecordRepository recordRepository,
                               SigningRecordOutboxRepository outboxRepository) {
        this.recordRepository = recordRepository;
        this.outboxRepository = outboxRepository;
    }

    // --- Inbound writes (REQUIRED) ---------------------------------------------------------------------

    /**
     * Persists one signing record. The entity carries an application-assigned UUID, so Spring Data routes the
     * {@code save} through a merge rather than a bare persist; {@code saveAndFlush} forces the flush now so a
     * constraint violation surfaces to the caller (and the strategy's metric scope) instead of being deferred
     * to commit.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insert(SigningRecord record) {
        recordRepository.saveAndFlush(record);
    }

    /**
     * Stages one signing record into the outbox. The entity carries an application-assigned UUID, so the
     * {@code save} runs as a merge; {@code saveAndFlush} forces the flush now so a constraint violation
     * surfaces synchronously, and the row is durable the moment the signing operation commits.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insertOutbox(SigningRecordOutbox row) {
        outboxRepository.saveAndFlush(row);
    }

    /**
     * Persists a batch of signing records in one transaction. Used by the best-effort flush, which runs on a
     * background thread with no ambient transaction, so {@code REQUIRED} opens one for the batch.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insertBatch(List<SigningRecord> records) {
        recordRepository.saveAll(records);
    }

    // --- Outbox drain (REQUIRES_NEW) -------------------------------------------------------------------

    /**
     * Persists one signing record and removes its originating outbox row, atomically in a single transaction.
     * The record carries an application-assigned UUID, so {@code saveAndFlush} runs as a merge-then-flush: the
     * flush forces the write to execute now, so a constraint violation is thrown to the caller instead of being
     * deferred to commit, and a pre-existing {@code signing_record} (crash recovery) is reconciled into a no-op
     * update. {@code delete} no-ops if the outbox row is already gone, so the copy is idempotent. The
     * orchestration around it — reading the outbox row, mapping it, and skipping an already-drained row — lives
     * in {@link com.czertainly.core.signing.record.SigningRecordOutboxDrainer}.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveRecordAndDeleteOutbox(SigningRecord record, SigningRecordOutbox outboxRow) {
        recordRepository.saveAndFlush(record);
        outboxRepository.delete(outboxRow);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID uuid, String error) {
        outboxRepository.recordFailure(List.of(uuid), truncateError(error));
    }

    // --- Deletions (REQUIRES_NEW) ----------------------------------------------------------------------

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void deleteByUuid(UUID uuid) {
        recordRepository.deleteByUuid(uuid);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteExpiredBatch(int limit) {
        return recordRepository.deleteExpiredByRetention(limit);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteRetrievedAndFlaggedBatch(int limit) {
        return recordRepository.deleteRetrievedAndFlagged(limit);
    }

    // --- Helpers ---------------------------------------------------------------------------------------

    /**
     * Caps the stored error to a sane length. A driver/constraint message (e.g. a full "could not execute
     * batch [...]" dump) can be huge and even embed the row's payload bytes; storing it verbatim would bloat
     * the {@code last_error} column. Keeping it bounded also keeps the failure UPDATE itself small and cheap,
     * so the attempt increment commits and poison escalation proceed.
     */
    private static String truncateError(String error) {
        if (error == null || error.length() <= MAX_ERROR_LENGTH) {
            return error;
        }
        return error.substring(0, MAX_ERROR_LENGTH);
    }
}
