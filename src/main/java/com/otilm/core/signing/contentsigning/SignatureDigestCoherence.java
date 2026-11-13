package com.otilm.core.signing.contentsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

/**
 * Refuses a content-signing run whose document digests differ from the digest its signer's signature algorithm commits
 * to. The refusal names input the caller can fix, ahead of the connector fault {@link DtbsBindingVerifier} would raise
 * after {@code computeDtbs}.
 */
public final class SignatureDigestCoherence {

    private SignatureDigestCoherence() {
    }

    /**
     * @throws SigningEngineException MISCONFIGURED if the algorithm commits to a digest the platform cannot name, or
     * INVALID_INPUT if the batch's digest algorithm differs from it
     */
    public static void requireCoherent(SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm)
            throws SigningEngineException {
        DigestAlgorithm committed = committedDigest(signatureAlgorithm);
        if (digestAlgorithm != committed) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "the batch's document digests are %s, but signature algorithm %s signs a %s digest"
                            .formatted(digestAlgorithm.getCode(), signatureAlgorithm.getCode(), committed.getCode()),
                    "The document digests are %s, but this Signing Profile signs a %s digest"
                            .formatted(digestAlgorithm.getCode(), committed.getCode()));
        }
    }

    /**
     * Every signature algorithm records the digest its signatures carry, including those whose name spells out none. An
     * identifier the platform has no {@link DigestAlgorithm} for can never fill the {@code documentDigestAlgorithm}
     * echo the binding gate needs, so the algorithm cannot be used for content signing at all -- which is a key or
     * profile choice, not a caller's mistake.
     */
    private static DigestAlgorithm committedDigest(SignatureAlgorithm signatureAlgorithm)
            throws SigningEngineException {
        String oid = signatureAlgorithm.getDigestAlgorithmIdentifier().getAlgorithm().getId();
        try {
            return DigestAlgorithm.findByOid(oid);
        } catch (ValidationException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signature algorithm '%s' commits to the digest identified by OID %s, which the platform has no digest algorithm for"
                            .formatted(signatureAlgorithm.getCode(), oid),
                    e, "Signing key algorithm %s cannot be used for content signing"
                            .formatted(signatureAlgorithm.getCode()));
        }
    }
}
