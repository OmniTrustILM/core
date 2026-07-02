package com.otilm.core.service.writer.signingrecord;

import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.signing.record.SigningRecordOutboxDrainer;
import jakarta.persistence.EntityManager;
import org.apache.commons.lang3.StringUtils;
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

    /**
     * Caps the stored error to a sane length. A driver/constraint message (e.g. a full "could not execute
     * batch [...]" dump) can be huge and even embed the row's payload bytes; storing it verbatim would bloat
     * the {@code last_error} column. Keeping it bounded also keeps the failure UPDATE itself small and cheap,
     * so the attempt increment commits and poison escalation proceed.
     */
    private static final int MAX_ERROR_LENGTH = 1000;

    private final EntityManager entityManager;
    private final SigningRecordRepository recordRepository;
    private final SigningRecordOutboxRepository outboxRepository;

    public SigningRecordWriter(EntityManager entityManager,
                               SigningRecordRepository recordRepository,
                               SigningRecordOutboxRepository outboxRepository) {
        this.entityManager = entityManager;
        this.recordRepository = recordRepository;
        this.outboxRepository = outboxRepository;
    }

    // --- Inbound writes (REQUIRED) ---------------------------------------------------------------------

    /**
     * Persists one signing record. Uses {@code EntityManager.persist()} directly to bypass Spring Data's merge
     * path (which issues a SELECT per entity for application-assigned UUIDs). The explicit {@code flush()} forces
     * the INSERT now so a constraint violation surfaces to the caller (and the strategy's metric scope) instead
     * of being deferred to commit.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insert(SigningRecord signingRecord) {
        entityManager.persist(signingRecord);
        entityManager.flush();
    }

    /**
     * Stages one signing record into the outbox. Uses {@code EntityManager.persist()} directly to bypass Spring
     * Data's merge path (which issues a SELECT per entity for application-assigned UUIDs). The explicit
     * {@code flush()} forces the INSERT now so a constraint violation surfaces synchronously, and the row is
     * durable the moment the signing operation commits.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insertOutbox(SigningRecordOutbox row) {
        entityManager.persist(row);
        entityManager.flush();
    }

    /**
     * Persists a batch of signing records in one transaction. Uses {@code EntityManager.persist()} directly
     * to bypass Spring Data's merge path (which issues a SELECT per entity for application-assigned UUIDs),
     * allowing Hibernate to batch the inserts using the configured {@code hibernate.jdbc.batch_size}.
     * Used by the best-effort flush, which runs on a background thread with no ambient transaction, so
     * {@code REQUIRED} opens one for the batch.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void insertBatch(List<SigningRecord> records) {
        records.forEach(entityManager::persist);
    }

    // --- Outbox drain (REQUIRES_NEW) -------------------------------------------------------------------

    /**
     * Bulk-drains a batch: persists all records in one transaction using Hibernate JDBC batching
     * ({@code hibernate.jdbc.batch_size=500}) and removes the originating outbox rows with a single bulk
     * DELETE. This is the fast path: one transaction and two round-trips per batch instead of one
     * transaction and four round-trips per row.
     *
     * <p>Uses {@code entityManager.persist()} directly to bypass Spring Data's merge path
     * ({@code save()} → {@code merge()} → SELECT-before-INSERT for application-assigned IDs). In the rare
     * crash-recovery case (a row already exists in {@code signing_record}) the flush will throw a
     * {@code PersistenceException}; the caller ({@link com.otilm.core.signing.record.SigningRecordOutboxDrainer})
     * catches that and falls back to per-row draining where each row gets individual retry/poison accounting.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void persistBatchAndDeleteOutbox(List<SigningRecord> records) {
        records.forEach(entityManager::persist);
        entityManager.flush();
        outboxRepository.deleteAllByUuidIn(records.stream().map(SigningRecord::getUuid).toList());
    }

    /**
     * Persists one signing record and removes its originating outbox row (which shares the record's UUID),
     * atomically in a single transaction. Used as the per-row fallback when the batch path fails (crash
     * recovery). The record carries an application-assigned UUID, so {@code saveAndFlush} runs as a
     * merge-then-flush: the flush forces the write to execute now, so a constraint violation is thrown to
     * the caller instead of being deferred to commit, and a pre-existing {@code signing_record}
     * (crash recovery) is reconciled into a no-op update. The outbox row is removed by id via
     * {@link SigningRecordOutboxRepository#deleteByUuid(UUID)} — a bare {@code DELETE} that reads no blobs
     * and no-ops if the row is already gone — so the copy is idempotent.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveRecordAndDeleteOutbox(SigningRecord signingRecord) {
        recordRepository.saveAndFlush(signingRecord);
        outboxRepository.deleteByUuid(signingRecord.getUuid());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID uuid, String error) {
        outboxRepository.recordFailure(List.of(uuid), StringUtils.truncate(error, MAX_ERROR_LENGTH));
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
}
