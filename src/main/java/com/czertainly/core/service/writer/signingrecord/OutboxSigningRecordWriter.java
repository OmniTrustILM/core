package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Owns both sides of the {@code signing_record_outbox} persistence for the {@code DEFERRED_DURABLE} mode:
 * <ul>
 *   <li>the inbound {@link #record(SigningRecordInput)} write strategy — stages a signing record into the
 *       outbox in the caller's transaction ({@link Propagation#REQUIRED}), so it is durable the moment the
 *       signing operation commits;</li>
 *   <li>the per-row drain back out into {@code signing_record}. {@link #drainRow(UUID)} and
 *       {@link #recordFailure(UUID, String)} each run in their own short {@link Propagation#REQUIRES_NEW}
 *       transaction so that one un-persistable row cannot poison the rest of a drain batch — see
 *       {@link SigningRecordOutboxDrainer}, which orchestrates the loop and holds the cluster-wide lock.</li>
 * </ul>
 * The {@code REQUIRES_NEW} drain methods must be invoked from another bean (the drainer); a self-invocation
 * would be a Spring proxy bypass and silently skip the transaction advice. Cross-node safety of the drain
 * rests on the idempotent copy (an assigned-id merge turns an already-present {@code signing_record} into a
 * no-op update) and the idempotent delete, not on holding a row lock across the drain.
 */
@Component
public class OutboxSigningRecordWriter implements SigningRecordWriter {

    private static final int MAX_ERROR_LENGTH = 1000;

    private final SigningRecordOutboxRepository outboxRepository;
    private final SigningRecordRepository recordRepository;
    private final SigningRecordMapper mapper;
    private final SigningRecordMetrics metrics;

    public OutboxSigningRecordWriter(SigningRecordOutboxRepository outboxRepository,
                                     SigningRecordRepository recordRepository,
                                     SigningRecordMapper mapper,
                                     SigningRecordMetrics metrics) {
        this.outboxRepository = outboxRepository;
        this.recordRepository = recordRepository;
        this.mapper = mapper;
        this.metrics = metrics;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(SigningRecordInput input) {
        if (!SigningRecordPolicy.hasAnyRecordableContent(input.getSigningProfile().recordPolicy())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        metrics.timed("DEFERRED_DURABLE", () -> {
            try {
                // saveAndFlush so a constraint violation surfaces inside the metric scope
                outboxRepository.saveAndFlush(mapper.toOutbox(input));
                metrics.outboxEnqueued().increment();
                metrics.created("DEFERRED_DURABLE").increment();
            } catch (RuntimeException e) {
                metrics.persistFailed("DEFERRED_DURABLE").increment();
                throw e;
            }
        });
    }

    /**
     * Copies one outbox row into {@code signing_record} and removes it from the outbox, atomically.
     * Returns {@code false} without doing anything if the row is already gone (drained by an earlier pass or
     * another node). The {@code saveAndFlush} forces the INSERT to execute now, so a constraint violation is
     * thrown to the caller instead of being deferred to commit; a pre-existing {@code signing_record} (crash
     * recovery) is reconciled via merge into a no-op update, making the copy idempotent.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean drainRow(UUID uuid) {
        SigningRecordOutbox row = outboxRepository.findById(uuid).orElse(null);
        if (row == null) {
            return false;
        }
        recordRepository.saveAndFlush(toRecord(row));
        outboxRepository.delete(row);
        return true;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID uuid, String error) {
        outboxRepository.recordFailure(List.of(uuid), truncateError(error));
    }

    /**
     * Caps the stored error to a sane length. A driver/constraint message (e.g. a full "could not execute
     * batch [...]" dump) can be huge and even embed the row's payload bytes; storing it verbatim would bloat
     * the {@code last_error} column. Keeping it bounded also keeps the failure UPDATE itself small and cheap,
     * so the attempt increment commits and poison escalation proceed.
     */
    private static String truncateError(String error) {
        if (error == null || error.length() <= MAX_ERROR_LENGTH) {
            return error;
        }
        return error.substring(0, MAX_ERROR_LENGTH);
    }

    private SigningRecord toRecord(SigningRecordOutbox row) {
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
        return r;
    }
}
