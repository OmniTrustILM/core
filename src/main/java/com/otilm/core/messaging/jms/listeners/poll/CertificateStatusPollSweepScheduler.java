package com.otilm.core.messaging.jms.listeners.poll;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Owns the periodic trigger that drives {@link CertificateStatusPollSweeper}. The sweeper holds all
 * advisory-lock/batch orchestration; this class holds only the schedule and the {@code scheduled-tasks.enabled}
 * gate. Keeping them apart mirrors the signing-record sweepers and lets the sweeper be unit-tested without
 * standing up the scheduling machinery.
 */
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class CertificateStatusPollSweepScheduler {

    private final CertificateStatusPollSweeper sweeper;

    public CertificateStatusPollSweepScheduler(CertificateStatusPollSweeper sweeper) {
        this.sweeper = sweeper;
    }

    @Scheduled(fixedDelayString = "${provider.status-poll.sweep-interval-ms:10000}")
    public void sweepScheduled() {
        sweeper.sweep();
    }
}
