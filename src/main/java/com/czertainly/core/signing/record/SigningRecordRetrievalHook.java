package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.core.cluster.ClusterOperationSynchronizer;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.service.writer.signingrecord.SigningRecordDeletionWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
public class SigningRecordRetrievalHook {

    private final SigningRecordRepository repository;
    private final SigningRecordDeletionWriter deletionWriter;
    private final SigningRecordMetrics metrics;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final int batchSize;
    private final int maxBatchesPerSweep;

    public SigningRecordRetrievalHook(SigningRecordRepository repository,
                                      SigningRecordDeletionWriter deletionWriter,
                                      SigningRecordMetrics metrics,
                                      ClusterOperationSynchronizer clusterSynchronizer,
                                      @Value("${signing-record.delete-after-retrieval.batch-size:1000}") int batchSize,
                                      @Value("${signing-record.delete-after-retrieval.max-batches-per-sweep:10}") int maxBatchesPerSweep) {
        this.repository = repository;
        this.deletionWriter = deletionWriter;
        this.metrics = metrics;
        this.clusterSynchronizer = clusterSynchronizer;
        this.batchSize = batchSize;
        this.maxBatchesPerSweep = maxBatchesPerSweep;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void onSignedDocumentServed(UUID signingRecordUuid) throws NotFoundException {
        SigningRecord record = repository.findById(signingRecordUuid)
                .orElseThrow(() -> new NotFoundException(SigningRecord.class, signingRecordUuid));

        record.setSignedDocumentRetrievedAt(Instant.now());
        repository.save(record);
        planSigningRecordDeletion(record);
    }

    private void planSigningRecordDeletion(SigningRecord r) {
        SigningProfile profile = r.getSigningProfile();
        if (profile == null || !profile.isDeleteAfterRetrieval()) {
            return;
        }

        UUID toDelete = r.getUuid();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                deleteRecordInTransaction(toDelete);
            }
        });
    }

    private void deleteRecordInTransaction(UUID toDelete) {
        try {
            deletionWriter.deleteByUuid(toDelete);
            metrics.retrievalDeleted().increment();
        } catch (RuntimeException e) {
            metrics.retrievalFailed().increment();
            log.warn("Post-retrieval delete failed for record {}", toDelete, e);
        }
    }

    /**
     * Holds the cluster-wide advisory lock for the sweep via this transaction (the lock is
     * transaction-scoped). Each batch deletes and commits in its own {@code REQUIRES_NEW}
     * transaction through {@link SigningRecordDeletionWriter}, so row locks and WAL release
     * incrementally — {@code signing_record} rows carry signed-document/signature/dtbs blobs, so a
     * single large delete would otherwise pin locks and the vacuum horizon while WAL accumulates.
     * The sweep deletes at most {@code maxBatchesPerSweep} batches per run; a large backlog clears
     * across several scheduled sweeps rather than one long-running transaction.
     */
    @Transactional
    public void runFallbackSweep() {
        if (maxBatchesPerSweep <= 0) {
            log.debug("Delete-after-retrieval fallback sweep disabled: max-batches-per-sweep is {}", maxBatchesPerSweep);
            return;
        }
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_DELETE_AFTER_RETRIEVAL)) {
            log.debug("Delete-after-retrieval fallback sweep skipped; another instance is already running it");
            return;
        }
        int total = 0;
        int batchesRun = 0;
        int deleted;
        do {
            deleted = deletionWriter.deleteRetrievedAndFlaggedBatch(batchSize);
            total += deleted;
            batchesRun++;
        } while (deleted == batchSize && batchesRun < maxBatchesPerSweep);
        if (deleted == batchSize) {
            log.debug("Delete-after-retrieval fallback sweep stopped at the per-sweep cap of {} batch(es); remaining flagged records clear on the next sweep",
                    maxBatchesPerSweep);
        }
        if (total > 0) {
            metrics.retrievalDeleted().increment(total);
            log.info("Delete-after-retrieval fallback sweep deleted {} record(s)", total);
        }
    }
}
