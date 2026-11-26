package com.otilm.core.signing.rawsigning;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * The signatures of a raw signing batch and what a relying party needs to verify them.
 *
 * @param signatureAlgorithm the algorithm every signature was made under
 * @param certificateChain the signing certificate first, followed by its CA certificates
 * @param items one per digest, in request order
 */
public record RawSigningResult(SignatureAlgorithm signatureAlgorithm, List<X509Certificate> certificateChain,
        List<RawSignedItem> items) {

    public RawSigningResult {
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        certificateChain = List.copyOf(Objects.requireNonNull(certificateChain, "certificateChain"));
        items = List.copyOf(Objects.requireNonNull(items, "items"));
    }
}
