package com.otilm.core.signing.contentsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

/**
 * Refuses a content-signing run whose authorized document digest is not the digest the resolved signer's signature
 * algorithm commits to. v1 profile policy pins the binding chain -- the authorized digest, a digest-only transfer's
 * digest and the connector's echo -- to that one algorithm for every family, because no request field names another one
 * to a connector. The engine applies the pin before {@code computeDtbs}, so a Signing Profile an operator can fix is
 * refused as input instead of reaching {@link DtbsBindingVerifier} as a connector fault.
 */
public final class SignatureDigestCoherence {

    private SignatureDigestCoherence() {
    }

    /**
     * @throws SigningEngineException MISCONFIGURED if the algorithm commits to a digest the platform cannot name, or
     * INVALID_INPUT if a supplied digest algorithm is not the one it commits to
     */
    public static void requireCoherent(SignatureAlgorithm signatureAlgorithm, DocumentDigest authorized,
            DocumentTransferDto document) throws SigningEngineException {
        DigestAlgorithm committed = committedDigest(signatureAlgorithm);
        requireCommittedDigest(signatureAlgorithm, committed, authorized.algorithm(), "the authorized document digest");
        if (document instanceof DigestOnlyDocumentTransferDto digestOnly) {
            requireCommittedDigest(signatureAlgorithm, committed, digestOnly.digestAlgorithm(),
                    "the submitted document digest");
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

    private static void requireCommittedDigest(SignatureAlgorithm signatureAlgorithm, DigestAlgorithm committed,
            DigestAlgorithm supplied, String which) throws SigningEngineException {
        if (supplied == committed) {
            return;
        }
        if (supplied == null) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "%s names no digest algorithm, but signature algorithm %s signs a %s digest"
                            .formatted(which, signatureAlgorithm.getCode(), committed.getCode()),
                    "The document digest names no algorithm, but this Signing Profile signs a %s digest"
                            .formatted(committed.getCode()));
        }
        throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                "%s is %s, but signature algorithm %s signs a %s digest"
                        .formatted(which, supplied.getCode(), signatureAlgorithm.getCode(), committed.getCode()),
                "The document digest is %s, but this Signing Profile signs a %s digest"
                        .formatted(supplied.getCode(), committed.getCode()));
    }
}
