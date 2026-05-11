package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

@Slf4j
@Component
public class SigningRecordRetrievalHook {

    private static final long FALLBACK_LOCK_KEY = 0x51_67_4E_43_52_44_52_00L;

    private final SigningRecordRepository repository;
    private final SigningRecordMetrics metrics;
    private final TransactionTemplate requiresNewTx;

    public SigningRecordRetrievalHook(SigningRecordRepository repository,
                                      SigningRecordMetrics metrics,
                                      PlatformTransactionManager txm) {
        this.repository = repository;
        this.metrics = metrics;
        this.requiresNewTx = new TransactionTemplate(txm);
        this.requiresNewTx.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void onSignedDocumentServed(UUID signingRecordUuid) {
        SigningRecord r = repository.findById(signingRecordUuid).orElse(null);
        if (r == null) {
            return;
        }
        r.setSignedDocumentRetrievedAt(OffsetDateTime.now());
        repository.save(r);

        if (r.getSigningProfile() != null && r.getSigningProfile().isDeleteAfterRetrieval()) {
            UUID toDelete = r.getUuid();
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    try {
                        requiresNewTx.executeWithoutResult(status -> repository.deleteById(toDelete));
                        metrics.retrievalDeleted().increment();
                    } catch (RuntimeException e) {
                        metrics.retrievalFailed().increment();
                        log.warn("Post-retrieval delete failed for record {}", toDelete, e);
                    }
                }
            });
        }
    }

    @Scheduled(cron = "${signing-record.delete-after-retrieval.fallback-cron:0 0 3 * * *}")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void runFallbackSweep() {
        if (!repository.tryAdvisoryLock(FALLBACK_LOCK_KEY)) {
            return;
        }
        try {
            int deleted = repository.deleteRetrievedAndFlagged();
            if (deleted > 0) {
                metrics.retrievalDeleted().increment(deleted);
                log.info("Delete-after-retrieval fallback sweep deleted {} record(s)", deleted);
            }
        } finally {
            repository.releaseAdvisoryLock(FALLBACK_LOCK_KEY);
        }
    }
}
