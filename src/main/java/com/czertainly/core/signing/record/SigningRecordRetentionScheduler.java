package com.czertainly.core.signing.record;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Owns the periodic trigger that drives {@link SigningRecordRetentionSweeper}. The sweeper holds all
 * advisory-lock/batch-delete orchestration; this class holds only the schedule and the
 * {@code scheduled-tasks.enabled} gate. Keeping them apart mirrors {@link SigningRecordOutboxDrainScheduler}
 * and lets the sweeper be unit- and integration-tested without standing up the scheduling machinery (which
 * would also activate {@code SystemScheduledJobs.registerJobs} and its external scheduler call).
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordRetentionScheduler {

    private final SigningRecordRetentionSweeper sweeper;

    public SigningRecordRetentionScheduler(SigningRecordRetentionSweeper sweeper) {
        this.sweeper = sweeper;
    }

    @Scheduled(fixedDelayString = "${signing-record.retention.sweep-interval-minutes}",
            timeUnit = TimeUnit.MINUTES)
    public void sweepScheduled() {
        sweeper.sweep();
    }
}
