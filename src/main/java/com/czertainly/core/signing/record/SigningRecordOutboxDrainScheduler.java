package com.czertainly.core.signing.record;

import com.czertainly.core.service.writer.signingrecord.OutboxSigningRecordWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Owns the periodic trigger that drives {@link SigningRecordOutboxDrainer}. The drainer holds all
 * claim/copy/poison/retry orchestration; this class holds only the schedule and the
 * {@code scheduled-tasks.enabled} gate. Keeping them apart mirrors {@link SigningRecordBestEffortFlusher}
 * and lets the drainer be unit- and integration-tested without standing up the scheduling machinery. The
 * drainer's outer transaction only holds the cluster-wide advisory lock; each row is copied in its own short
 * transaction through {@link OutboxSigningRecordWriter}.
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordOutboxDrainScheduler {

    private final SigningRecordOutboxDrainer drainer;

    public SigningRecordOutboxDrainScheduler(SigningRecordOutboxDrainer drainer) {
        this.drainer = drainer;
    }

    @Scheduled(fixedDelayString = "${signing-record.outbox.flush-interval-ms:500}")
    public void drainScheduled() {
        drainer.drainOnce();
    }
}
