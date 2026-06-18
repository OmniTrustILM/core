package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

class SigningRecordStrategyFactoryTest {

    private final ImmediateSigningRecordStrategy immediate = Mockito.mock(ImmediateSigningRecordStrategy.class);
    private final DeferredDurableSigningRecordStrategy deferredDurable = Mockito.mock(DeferredDurableSigningRecordStrategy.class);
    private final BestEffortSigningRecordStrategy bestEffort = Mockito.mock(BestEffortSigningRecordStrategy.class);

    private final SigningRecordStrategyFactory factory =
            new SigningRecordStrategyFactory(immediate, deferredDurable, bestEffort);

    @Test
    void returnsImmediateForImmediateMode() {
        assertSame(immediate, factory.strategyFor(SigningRecordPersistenceMode.IMMEDIATE));
    }

    @Test
    void returnsDeferredDurableForDeferredDurableMode() {
        assertSame(deferredDurable, factory.strategyFor(SigningRecordPersistenceMode.DEFERRED_DURABLE));
    }

    @Test
    void returnsBestEffortForBestEffortMode() {
        assertSame(bestEffort, factory.strategyFor(SigningRecordPersistenceMode.BEST_EFFORT));
    }

    @Test
    void defaultsToDeferredDurableWhenModeIsNull() {
        assertSame(deferredDurable, factory.strategyFor(null));
    }
}
