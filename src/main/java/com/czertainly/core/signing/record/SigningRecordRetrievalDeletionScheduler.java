package com.czertainly.core.signing.record;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Owns the periodic trigger that drives {@link SigningRecordRetrievalHook#runFallbackSweep()}. The hook holds
 * all delete-after-retrieval orchestration (the per-retrieval {@code afterCommit} delete plus the
 * cluster-locked fallback sweep); this class holds only the cron schedule and the
 * {@code scheduled-tasks.enabled} gate. Keeping them apart mirrors {@link SigningRecordRetentionScheduler}
 * and lets the hook be unit- and integration-tested without standing up the scheduling machinery.
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordRetrievalDeletionScheduler {

    private final SigningRecordRetrievalHook hook;

    public SigningRecordRetrievalDeletionScheduler(SigningRecordRetrievalHook hook) {
        this.hook = hook;
    }

    @Scheduled(cron = "${signing-record.delete-after-retrieval.fallback-cron:0 0 3 * * *}")
    public void runFallbackSweepScheduled() {
        hook.runFallbackSweep();
    }
}
