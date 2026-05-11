package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.signing.record.BestEffortSigningRecordWriter;
import com.czertainly.core.signing.record.ImmediateSigningRecordWriter;
import com.czertainly.core.signing.record.OutboxSigningRecordWriter;
import com.czertainly.core.signing.record.SigningRecordWriterFactory;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

class SigningRecordWriterFactoryTest {

    private final ImmediateSigningRecordWriter immediate = Mockito.mock(ImmediateSigningRecordWriter.class);
    private final OutboxSigningRecordWriter outbox = Mockito.mock(OutboxSigningRecordWriter.class);
    private final BestEffortSigningRecordWriter bestEffort = Mockito.mock(BestEffortSigningRecordWriter.class);

    private final SigningRecordWriterFactory factory =
            new SigningRecordWriterFactory(immediate, outbox, bestEffort);

    private SigningProfile profile(SigningRecordPersistenceMode mode) {
        SigningProfile p = new SigningProfile();
        p.setPersistenceMode(mode);
        return p;
    }

    @Test
    void returnsImmediateForImmediateMode() {
        assertSame(immediate, factory.writerFor(profile(SigningRecordPersistenceMode.IMMEDIATE)));
    }

    @Test
    void returnsOutboxForDeferredDurableMode() {
        assertSame(outbox, factory.writerFor(profile(SigningRecordPersistenceMode.DEFERRED_DURABLE)));
    }

    @Test
    void returnsBestEffortForBestEffortMode() {
        assertSame(bestEffort, factory.writerFor(profile(SigningRecordPersistenceMode.BEST_EFFORT)));
    }
}
