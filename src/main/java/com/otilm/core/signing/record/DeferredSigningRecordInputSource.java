package com.otilm.core.signing.record;

import com.otilm.core.model.signing.SigningProfileModel;

import java.util.function.Supplier;

/**
 * Protocol-agnostic {@link SigningRecordInputSource} that exposes the signing profile eagerly — so a strategy can
 * evaluate the {@code recordingEnabled} gate and emit intake metrics — while deferring the (potentially expensive)
 * assembly of the full input to the supplied callback, which runs only when {@link #build()} is called.
 *
 * <p>Any per-protocol record factory (TSP, CSC, …) can return one of these: it captures the profile up front and
 * wraps that protocol's own input-assembly as the deferred {@code inputSupplier}.
 */
public final class DeferredSigningRecordInputSource implements SigningRecordInputSource {

    private final SigningProfileModel<?, ?> signingProfile;
    private final Supplier<SigningRecordInput> inputSupplier;

    public DeferredSigningRecordInputSource(SigningProfileModel<?, ?> signingProfile,
                                            Supplier<SigningRecordInput> inputSupplier) {
        this.signingProfile = signingProfile;
        this.inputSupplier = inputSupplier;
    }

    @Override
    public SigningProfileModel<?, ?> signingProfile() {
        return signingProfile;
    }

    @Override
    public SigningRecordInput build() {
        return inputSupplier.get();
    }
}
