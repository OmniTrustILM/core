package com.czertainly.core.signing.record;

import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordRetentionSweeper {

    private static final long ADVISORY_LOCK_KEY = 0x51_67_4E_43_52_45_43_00L;

    private final SigningRecordRepository repository;
    private final SigningRecordMetrics metrics;

    public SigningRecordRetentionSweeper(SigningRecordRepository repository, SigningRecordMetrics metrics) {
        this.repository = repository;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${signing-record.retention.sweep-interval-minutes:60}",
            timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void sweep() {
        if (!repository.tryAdvisoryLock(ADVISORY_LOCK_KEY)) {
            log.debug("Retention sweep skipped: another instance holds the lock");
            return;
        }
        try {
            int deleted = repository.deleteExpiredByRetention();
            if (deleted > 0) {
                metrics.retentionDeleted().increment(deleted);
                log.info("Retention sweep deleted {} signing record(s)", deleted);
            }
        } finally {
            repository.releaseAdvisoryLock(ADVISORY_LOCK_KEY);
        }
    }
}
