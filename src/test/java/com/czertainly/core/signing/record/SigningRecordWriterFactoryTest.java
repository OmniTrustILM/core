package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.service.writer.signingrecord.BestEffortSigningRecordWriter;
import com.czertainly.core.service.writer.signingrecord.ImmediateSigningRecordWriter;
import com.czertainly.core.service.writer.signingrecord.OutboxSigningRecordWriter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

class SigningRecordWriterFactoryTest {

    private final ImmediateSigningRecordWriter immediate = Mockito.mock(ImmediateSigningRecordWriter.class);
    private final OutboxSigningRecordWriter outbox = Mockito.mock(OutboxSigningRecordWriter.class);
    private final BestEffortSigningRecordWriter bestEffort = Mockito.mock(BestEffortSigningRecordWriter.class);

    private final SigningRecordWriterFactory factory =
            new SigningRecordWriterFactory(immediate, outbox, bestEffort);

    private SigningProfileVersion version(SigningRecordPersistenceMode mode) {
        SigningProfileVersion v = new SigningProfileVersion();
        v.setPersistenceMode(mode);
        return v;
    }

    @Test
    void returnsImmediateForImmediateMode() {
        assertSame(immediate, factory.writerFor(version(SigningRecordPersistenceMode.IMMEDIATE)));
    }

    @Test
    void returnsOutboxForDeferredDurableMode() {
        assertSame(outbox, factory.writerFor(version(SigningRecordPersistenceMode.DEFERRED_DURABLE)));
    }

    @Test
    void returnsBestEffortForBestEffortMode() {
        assertSame(bestEffort, factory.writerFor(version(SigningRecordPersistenceMode.BEST_EFFORT)));
    }
}
