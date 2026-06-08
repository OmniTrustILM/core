package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
import org.springframework.stereotype.Component;

/**
 * {@code DEFERRED_DURABLE} mode: stages the record into {@code signing_record_outbox} in the caller's
 * transaction, so it is durable the moment the signing operation commits. The asynchronous copy out into
 * {@code signing_record} is owned by {@link SigningRecordOutboxDrainer} via the writer's drain methods.
 */
@Component
public class DeferredDurableSigningRecordStrategy extends AbstractSigningRecordStrategy {

    private final SigningRecordWriter writer;
    private final SigningRecordInputMapper mapper;

    public DeferredDurableSigningRecordStrategy(SigningRecordMetrics metrics,
                                                SigningRecordWriter writer,
                                                SigningRecordInputMapper mapper) {
        super(metrics);
        this.writer = writer;
        this.mapper = mapper;
    }

    @Override
    protected void doRecord(SigningRecordInput input) {
        try {
            writer.insertOutbox(mapper.toOutbox(input));
            metrics.outboxEnqueued().increment();
            metrics.created(mode().name()).increment();
        } catch (RuntimeException e) {
            metrics.persistFailed(mode().name()).increment();
            throw e;
        }
    }

    @Override
    protected SigningRecordPersistenceMode mode() {
        return SigningRecordPersistenceMode.DEFERRED_DURABLE;
    }
}
