package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.SigningRecordRetentionSweeper;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Commits signing-record deletes, each in its own transaction ({@link Propagation#REQUIRES_NEW}), so that
 * batches release row locks and flush WAL incrementally rather than accumulating into a caller's
 * lock-holding transaction. A separate bean is required: a {@code REQUIRES_NEW} call from within the
 * orchestrating service or sweeper would be a proxy self-invocation and silently skip the transaction advice.
 *
 * <p>Two delete paths share this guarantee:
 * <ul>
 *     <li>{@link #deleteByUuid(UUID)} — operator-initiated bulk deletion, where committing per row keeps one
 *     failing row from rolling back the rest of a best-effort batch
 *     (see {@link com.czertainly.core.service.impl.SigningRecordServiceImpl#bulkDeleteSigningRecords});</li>
 *     <li>{@link #deleteExpiredBatch(int)} — the scheduled retention sweep, where committing per batch keeps
 *     the sweep's advisory-lock transaction from pinning row locks and the vacuum horizon
 *     (see {@link SigningRecordRetentionSweeper}).</li>
 * </ul>
 */
@Component
public class SigningRecordDeletionWriter {

    private final SigningRecordRepository repository;

    public SigningRecordDeletionWriter(SigningRecordRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void deleteByUuid(UUID uuid) {
        repository.deleteByUuid(uuid);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteExpiredBatch(int limit) {
        return repository.deleteExpiredByRetention(limit);
    }
}
