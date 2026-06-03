package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.core.cluster.ClusterOperationSynchronizer;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
public class SigningRecordRetrievalHook {

    private final SigningRecordRepository repository;
    private final SigningRecordMetrics metrics;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final TransactionTemplate requiresNewTx;

    public SigningRecordRetrievalHook(SigningRecordRepository repository,
                                      SigningRecordMetrics metrics,
                                      ClusterOperationSynchronizer clusterSynchronizer,
                                      PlatformTransactionManager txm) {
        this.repository = repository;
        this.metrics = metrics;
        this.clusterSynchronizer = clusterSynchronizer;
        this.requiresNewTx = new TransactionTemplate(txm);
        // The post-retrieval delete runs in afterCommit(), where the original transaction has
        // already committed but is still bound to the thread. REQUIRES_NEW suspends it and opens
        // a fresh transaction, so delete can actually commit (and potentially fail in isolation).
        this.requiresNewTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
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
            requiresNewTx.executeWithoutResult(status -> repository.deleteById(toDelete));
            metrics.retrievalDeleted().increment();
        } catch (RuntimeException e) {
            metrics.retrievalFailed().increment();
            log.warn("Post-retrieval delete failed for record {}", toDelete, e);
        }
    }

    @Scheduled(cron = "${signing-record.delete-after-retrieval.fallback-cron:0 0 3 * * *}")
    @Transactional
    public void runFallbackSweep() {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_DELETE_AFTER_RETRIEVAL)) {
            log.debug("Delete-after-retrieval fallback sweep skipped; another instance is already running it");
            return;
        }
        int deleted = repository.deleteRetrievedAndFlagged();
        if (deleted > 0) {
            metrics.retrievalDeleted().increment(deleted);
            log.info("Delete-after-retrieval fallback sweep deleted {} record(s)", deleted);
        }
    }
}
