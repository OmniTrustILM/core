package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.util.EnumSet;
import java.util.Set;

/**
 * The signature algorithms that may sign a client-supplied digest: RSA PKCS#1 v1.5, RSA-PSS and ECDSA over SHA-2. Each
 * fixes the digest it signs and can be checked against the signing key's public key, which a prehashed signature needs
 * because no provider can be trusted to have honored the mode. Both the prehashed signing path and a raw profile's save
 * check against this one set.
 */
public final class PrehashedSigning {

    private static final Set<SignatureAlgorithm> ADMITTED = EnumSet
            .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                    SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                    SignatureAlgorithm.SHA512_WITH_ECDSA);

    private PrehashedSigning() {
    }

    public static boolean admits(SignatureAlgorithm algorithm) {
        return algorithm != null && ADMITTED.contains(algorithm);
    }

    /**
     * @throws IllegalArgumentException if the algorithm is outside the bound
     */
    public static DigestAlgorithm digestAlgorithm(SignatureAlgorithm algorithm) {
        if (!admits(algorithm)) {
            throw new IllegalArgumentException("Signature algorithm %s cannot sign a prehashed digest"
                    .formatted(algorithm == null ? null : algorithm.getCode()));
        }
        return DigestAlgorithm.findByOid(algorithm.getDigestAlgorithmIdentifier().getAlgorithm().getId());
    }
}
