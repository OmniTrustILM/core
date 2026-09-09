package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes to the bounded-retry record of the CBOM header sync.
 *
 * <p>
 * Every method is {@code REQUIRED}, so it commits in its own transaction when the sync loop -- which runs without one,
 * because it pages an external service -- calls it after the entry's own transaction has already rolled back. Called
 * from inside that failing transaction it would be rolled back with it, and the failure would be lost; owning that
 * boundary is the sync loop's job.
 */
@Service
public class CbomSyncSkipWriter {

    private final CbomSyncSkipRepository repository;

    public CbomSyncSkipWriter(CbomSyncSkipRepository repository) {
        this.repository = repository;
    }

    /**
     * Counts a failed attempt and returns the row as it now stands, so the caller can tell whether the budget is spent.
     *
     * @param operatorSafeReason text the caller shaped itself; stored verbatim and shown to an operator, so never a
     * driver or framework message
     */
    @Transactional
    public CbomSyncSkip recordAttempt(String serialNumber, int version, String operatorSafeReason,
            CbomHeaderCounts counts, OffsetDateTime now, int maxAttempts) {
        repository
                .upsertAttempt(UUID.randomUUID(), serialNumber, version, operatorSafeReason, now, maxAttempts, counts);
        return repository
                .findBySerialNumberAndVersion(serialNumber, version)
                .orElseThrow(() -> new IllegalStateException(
                        "cbom_sync_skip row vanished between its upsert and its read for " + serialNumber + " version "
                                + version));
    }

    /** Forgets the record: the document is stored. Returns 0 when there was none. */
    @Transactional
    public int resolve(String serialNumber, int version) {
        return repository.deleteBySerialNumberAndVersion(serialNumber, version);
    }
}
