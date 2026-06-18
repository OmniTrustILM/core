package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import org.springframework.stereotype.Component;

@Component
public class SigningRecordStrategyFactory {

    private final ImmediateSigningRecordStrategy immediate;
    private final DeferredDurableSigningRecordStrategy deferredDurable;
    private final BestEffortSigningRecordStrategy bestEffort;

    public SigningRecordStrategyFactory(ImmediateSigningRecordStrategy immediate,
                                        DeferredDurableSigningRecordStrategy deferredDurable,
                                        BestEffortSigningRecordStrategy bestEffort) {
        this.immediate = immediate;
        this.deferredDurable = deferredDurable;
        this.bestEffort = bestEffort;
    }

    public SigningRecordStrategy strategyFor(SigningRecordPersistenceMode mode) {
        SigningRecordPersistenceMode effectiveMode = mode != null ? mode : SigningRecordPersistenceMode.DEFERRED_DURABLE;
        return switch (effectiveMode) {
            case IMMEDIATE -> immediate;
            case DEFERRED_DURABLE -> deferredDurable;
            case BEST_EFFORT -> bestEffort;
        };
    }
}
