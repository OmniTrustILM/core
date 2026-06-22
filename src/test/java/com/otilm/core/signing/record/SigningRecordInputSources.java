package com.otilm.core.signing.record;

/**
 * Test-only adapter from a materialized {@link SigningRecordInput} to a {@link SigningRecordInputSource}.
 * Production code always supplies a genuinely deferred source (see
 * {@code com.otilm.core.signing.tsa.TspSigningRecordFactory#source}); tests that already hold a built input use
 * this to feed a strategy without redundantly deferring the build.
 */
public final class SigningRecordInputSources {

    private SigningRecordInputSources() {
    }

    public static SigningRecordInputSource of(SigningRecordInput input) {
        return new DeferredSigningRecordInputSource(input.getSigningProfile(), () -> input);
    }
}
