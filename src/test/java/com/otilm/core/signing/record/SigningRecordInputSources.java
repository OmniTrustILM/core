package com.otilm.core.signing.record;

import java.util.List;
import java.util.UUID;

/**
 * Test-only adapter from a materialized {@link SigningRecordInput} to a {@link SigningRecordInputSource}. Production
 * code always supplies a genuinely deferred source (see
 * {@code com.otilm.core.signing.tsa.TimestampSigningRecordFactory#source}); tests that already hold a built input use
 * this to feed a strategy without redundantly deferring the build.
 */
public final class SigningRecordInputSources {

    private SigningRecordInputSources() {
    }

    public static SigningRecordInputSource of(SigningRecordInput input) {
        return new DeferredSigningRecordInputSource(input.getSigningProfile(), () -> input);
    }

    /** Records the input as a batch of one, as the engines that sign one operation at a time do. */
    public static List<UUID> recordOne(SigningRecordStrategy strategy, SigningRecordInput input) {
        return strategy.record(input.getSigningProfile(), List.of(of(input)));
    }
}
