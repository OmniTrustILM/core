package com.otilm.core.signing.rawsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import java.util.List;
import java.util.Objects;

/**
 * A batch of digests for a raw signing run. The mode and the digest algorithm are what the caller claims; the run
 * checks both against the profile, so either may be {@code null} here.
 *
 * @param inputMode what each item is, as the caller states it
 * @param digestAlgorithm the algorithm the caller says produced every digest
 * @param items the digests in request order
 */
public record RawSigningRequest(SignatureInputMode inputMode, DigestAlgorithm digestAlgorithm,
        List<RawSigningItem> items) {

    public RawSigningRequest {
        items = List.copyOf(Objects.requireNonNull(items, "items"));
    }
}
