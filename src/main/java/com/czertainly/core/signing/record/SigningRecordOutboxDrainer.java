package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordOutboxDrainer {

    private final SigningRecordOutboxRepository outboxRepo;
    private final SigningRecordRepository recordRepo;
    private final SigningRecordMetrics metrics;

    private final int batchSize;
    private final int poisonThreshold;

    public SigningRecordOutboxDrainer(SigningRecordOutboxRepository outboxRepo,
                                      SigningRecordRepository recordRepo,
                                      SigningRecordMetrics metrics,
                                      @Value("${signing-record.outbox.max-batch-size:200}") int batchSize,
                                      @Value("${signing-record.outbox.poison-threshold:10}") int poisonThreshold) {
        this.outboxRepo = outboxRepo;
        this.recordRepo = recordRepo;
        this.metrics = metrics;
        this.batchSize = batchSize;
        this.poisonThreshold = poisonThreshold;
    }

    @Scheduled(fixedDelayString = "${signing-record.outbox.flush-interval-ms:500}")
    public void drainOnce() {
        try {
            drainTransaction(); // :TODO:
        } catch (RuntimeException e) {
            log.warn("Outbox drain iteration failed", e);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void drainTransaction() {
        List<SigningRecordOutbox> claimed = outboxRepo.claimBatchSkipLocked(batchSize);
        if (claimed.isEmpty())
            return;

        List<SigningRecordOutbox> work = new ArrayList<>(claimed.size());
        for (SigningRecordOutbox row : claimed) {
            if (row.getAttempts() >= poisonThreshold) {
                metrics.outboxPoison().increment();
                log.error("Outbox row {} reached poison threshold (attempts={}, lastError={})",
                        row.getUuid(), row.getAttempts(), row.getLastError());
                continue;
            }
            work.add(row);
        }
        if (work.isEmpty())
            return;

        List<UUID> processed = new ArrayList<>(work.size());
        for (SigningRecordOutbox row : work) {
            try {
                SigningRecord r = new SigningRecord();
                r.setUuid(row.getUuid());
                r.setName(row.getName());
                r.setSigningProfileUuid(row.getSigningProfileUuid());
                r.setSigningProfileVersion(row.getSigningProfileVersion());
                r.setSigningTime(row.getSigningTime());
                r.setSignatureValue(row.getSignatureValue());
                r.setSignedDocument(row.getSignedDocument());
                r.setDtbs(row.getDtbs());
                r.setRequestMetadataJson(row.getRequestMetadataJson());
                recordRepo.save(r);
                processed.add(row.getUuid());
            } catch (DataIntegrityViolationException dup) {
                log.info("Outbox row {} already in signing_record; treating as drained", row.getUuid());
                processed.add(row.getUuid());
            } catch (RuntimeException e) {
                metrics.outboxFailed().increment();
                outboxRepo.recordFailure(List.of(row.getUuid()), e.getMessage());
                log.warn("Failed to drain outbox row {}", row.getUuid(), e);
            }
        }
        if (!processed.isEmpty()) {
            outboxRepo.deleteAllById(processed);
            metrics.outboxDrained().increment();
        }
    }
}
