package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.service.writer.signingrecord.BestEffortSigningRecordWriter;
import com.czertainly.core.service.writer.signingrecord.ImmediateSigningRecordWriter;
import com.czertainly.core.service.writer.signingrecord.OutboxSigningRecordWriter;
import org.springframework.stereotype.Component;

@Component
public class SigningRecordWriterFactory {

    private final ImmediateSigningRecordWriter immediate;
    private final OutboxSigningRecordWriter outbox;
    private final BestEffortSigningRecordWriter bestEffort;

    public SigningRecordWriterFactory(ImmediateSigningRecordWriter immediate,
                                      OutboxSigningRecordWriter outbox,
                                      BestEffortSigningRecordWriter bestEffort) {
        this.immediate = immediate;
        this.outbox = outbox;
        this.bestEffort = bestEffort;
    }

    public SigningRecordWriter writerFor(SigningProfileVersion version) {
        SigningRecordPersistenceMode mode = version.getPersistenceMode() != null
                ? version.getPersistenceMode()
                : SigningRecordPersistenceMode.DEFERRED_DURABLE;
        return switch (mode) {
            case IMMEDIATE -> immediate;
            case DEFERRED_DURABLE -> outbox;
            case BEST_EFFORT -> bestEffort;
        };
    }
}
