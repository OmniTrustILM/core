package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

class SigningRecordStrategyFactoryTest {

    private final ImmediateSigningRecordStrategy immediate = Mockito.mock(ImmediateSigningRecordStrategy.class);
    private final DeferredDurableSigningRecordStrategy deferredDurable = Mockito.mock(DeferredDurableSigningRecordStrategy.class);
    private final BestEffortSigningRecordStrategy bestEffort = Mockito.mock(BestEffortSigningRecordStrategy.class);

    private final SigningRecordStrategyFactory factory =
            new SigningRecordStrategyFactory(immediate, deferredDurable, bestEffort);

    private SigningProfileVersion version(SigningRecordPersistenceMode mode) {
        SigningProfileVersion v = new SigningProfileVersion();
        v.setPersistenceMode(mode);
        return v;
    }

    @Test
    void returnsImmediateForImmediateMode() {
        assertSame(immediate, factory.strategyFor(version(SigningRecordPersistenceMode.IMMEDIATE)));
    }

    @Test
    void returnsDeferredDurableForDeferredDurableMode() {
        assertSame(deferredDurable, factory.strategyFor(version(SigningRecordPersistenceMode.DEFERRED_DURABLE)));
    }

    @Test
    void returnsBestEffortForBestEffortMode() {
        assertSame(bestEffort, factory.strategyFor(version(SigningRecordPersistenceMode.BEST_EFFORT)));
    }

    @Test
    void defaultsToDeferredDurableWhenModeIsNull() {
        assertSame(deferredDurable, factory.strategyFor(version(null)));
    }
}
