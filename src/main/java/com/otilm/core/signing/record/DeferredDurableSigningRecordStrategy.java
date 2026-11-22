package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * {@code DEFERRED_DURABLE} mode: stages the record into {@code signing_record_outbox} in the caller's transaction, so
 * it is durable the moment the signing operation commits. The asynchronous copy out into {@code signing_record} is
 * owned by {@link SigningRecordOutboxDrainer} via the writer's drain methods.
 */
@Component
public class DeferredDurableSigningRecordStrategy extends AbstractSigningRecordStrategy {

    private final SigningRecordWriter writer;
    private final SigningRecordInputMapper mapper;

    public DeferredDurableSigningRecordStrategy(SigningRecordMetrics metrics, SigningRecordWriter writer,
            SigningRecordInputMapper mapper) {
        super(metrics);
        this.writer = writer;
        this.mapper = mapper;
    }

    @Override
    protected List<UUID> doRecord(List<SigningRecordInput> inputs) {
        List<SigningRecordOutbox> rows = inputs.stream().map(mapper::toOutbox).toList();
        try {
            writer.insertOutboxBatch(rows);
        } catch (RuntimeException e) {
            metrics.intakeFailed(mode().name(), SigningRecordMetrics.REASON_SAVE_ERROR).increment(rows.size());
            throw e;
        }
        return rows.stream().map(SigningRecordOutbox::getUuid).toList();
    }

    @Override
    protected SigningRecordPersistenceMode mode() {
        return SigningRecordPersistenceMode.DEFERRED_DURABLE;
    }
}
