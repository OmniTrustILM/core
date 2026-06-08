package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
import org.springframework.stereotype.Component;

/**
 * {@code IMMEDIATE} mode: maps and persists the record synchronously in the caller's transaction. There is no
 * queue and no deferral — a persistence failure propagates to the caller.
 */
@Component
public class ImmediateSigningRecordStrategy extends AbstractSigningRecordStrategy {

    private final SigningRecordWriter writer;
    private final SigningRecordInputMapper mapper;

    public ImmediateSigningRecordStrategy(SigningRecordMetrics metrics,
                                          SigningRecordWriter writer,
                                          SigningRecordInputMapper mapper) {
        super(metrics);
        this.writer = writer;
        this.mapper = mapper;
    }

    @Override
    protected void doRecord(SigningRecordInput input) {
        try {
            writer.insert(mapper.toRecord(input));
            metrics.created(mode().name()).increment();
        } catch (RuntimeException e) {
            metrics.persistFailed(mode().name()).increment();
            throw e;
        }
    }

    @Override
    protected SigningRecordPersistenceMode mode() {
        return SigningRecordPersistenceMode.IMMEDIATE;
    }
}
