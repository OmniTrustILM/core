package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * {@code IMMEDIATE} mode: maps and persists the record synchronously in the caller's transaction. There is no queue and
 * no deferral — a persistence failure propagates to the caller.
 */
@Component
public class ImmediateSigningRecordStrategy extends AbstractSigningRecordStrategy {

    private final SigningRecordWriter writer;
    private final SigningRecordInputMapper mapper;

    public ImmediateSigningRecordStrategy(SigningRecordMetrics metrics, SigningRecordWriter writer,
            SigningRecordInputMapper mapper) {
        super(metrics);
        this.writer = writer;
        this.mapper = mapper;
    }

    @Override
    protected List<UUID> doRecord(List<SigningRecordInput> inputs) {
        metrics.persist(mode().name()).increment(inputs.size());
        List<SigningRecord> signingRecords = inputs.stream().map(mapper::toRecord).toList();
        try {
            writer.insertBatch(signingRecords);
        } catch (RuntimeException e) {
            metrics.persistFailed(mode().name()).increment(signingRecords.size());
            metrics
                    .intakeFailed(mode().name(), SigningRecordMetrics.REASON_PERSIST_ERROR)
                    .increment(signingRecords.size());
            throw e;
        }
        return signingRecords.stream().map(SigningRecord::getUuid).toList();
    }

    @Override
    protected SigningRecordPersistenceMode mode() {
        return SigningRecordPersistenceMode.IMMEDIATE;
    }
}
