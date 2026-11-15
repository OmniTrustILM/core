package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Verifies that the data-to-be-signed a formatting connector produced is bound to the document the caller authorized.
 * The engine runs this before the signing key signs.
 *
 * <p>
 * The check compares the connector's echoed {@code documentDigest} against the digest authorized when the operation was
 * accepted. The platform never parses the data-to-be-signed and never re-derives the digest, so the connector must echo
 * the digest it committed to. PAdES, XAdES, CAdES and JAdES all satisfy the rule the same way; raw signing carries no
 * echo, because there the client submits the digest itself.
 * </p>
 */
public final class DtbsBindingVerifier {

    private static final String STEP = "computeDtbs";

    private static final String MISMATCH_CLIENT_MESSAGE = "The document the signature would cover is not the document that was authorized";

    private static final String BROKEN_ECHO_CLIENT_MESSAGE = "Internal error during signature formatting";

    private DtbsBindingVerifier() {
    }

    /**
     * Verifies the echo a {@code computeDtbs} response carries against the authorized digest.
     *
     * @throws IllegalArgumentException if the authorized digest is not as long as its algorithm produces
     * @throws SigningEngineException if the response or its echo is missing, unusable or bound to a different document
     */
    public static void verify(DocumentDigest authorized, ComputeDtbsResponseDto response)
            throws SigningEngineException {
        if (response == null) {
            throw brokenEcho("connector returned no computeDtbs response");
        }
        verifyEcho(authorized, requireCompleteEcho(response));
    }

    /**
     * Verifies an echoed digest against the authorized digest.
     *
     * @param echoed the digest the connector committed to, or {@code null} when it echoed none
     * @throws IllegalArgumentException if the authorized digest is not as long as its algorithm produces
     * @throws SigningEngineException if the echo is missing, unusable or bound to a different document
     */
    public static void verifyEcho(DocumentDigest authorized, DocumentDigest echoed) throws SigningEngineException {
        requireWellFormedAuthorizedDigest(authorized);
        if (echoed == null) {
            throw brokenEcho("connector echoed no documentDigest");
        }
        requireUsableEcho(authorized, echoed);
        if (!MessageDigest.isEqual(authorized.value(), echoed.value())) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.BINDING_VIOLATION, STEP,
                            "connector committed to %s but %s was authorized".formatted(echoed, authorized), null,
                            MISMATCH_CLIENT_MESSAGE);
        }
    }

    /**
     * A malformed authorized digest is a platform defect, and every echo would mismatch it. Rejecting it here keeps
     * {@link SigningEngineFailure#BINDING_VIOLATION} for the case where the documents genuinely differ.
     */
    private static void requireWellFormedAuthorizedDigest(DocumentDigest authorized) {
        Objects.requireNonNull(authorized, "authorized");
        if (!authorized.hasLengthOfItsAlgorithm()) {
            throw new IllegalArgumentException("Authorized digest is %d bytes, which %s never produces"
                    .formatted(authorized.length(), authorized.algorithm().getCode()));
        }
    }

    /**
     * An echo is only usable with both halves present. Naming the half that is missing points whoever debugs the
     * connector at the field actually at fault, rather than at the one that is populated.
     */
    private static DocumentDigest requireCompleteEcho(ComputeDtbsResponseDto response) throws SigningEngineException {
        DigestAlgorithm algorithm = response.getDocumentDigestAlgorithm();
        byte[] digest = response.getDocumentDigest();
        if (algorithm == null && digest == null) {
            throw brokenEcho("connector echoed no documentDigest");
        }
        if (digest == null) {
            throw brokenEcho("connector echoed a %s documentDigestAlgorithm but no documentDigest"
                    .formatted(algorithm.getCode()));
        }
        if (algorithm == null) {
            throw brokenEcho("connector echoed a %d-byte documentDigest but no documentDigestAlgorithm"
                    .formatted(digest.length));
        }
        return new DocumentDigest(algorithm, digest);
    }

    /**
     * An echo of the wrong algorithm or of a length its algorithm never produces proves the connector broke the
     * contract, not that the document differs — so it must not reach the caller as a mismatch.
     */
    private static void requireUsableEcho(DocumentDigest authorized, DocumentDigest echoed)
            throws SigningEngineException {
        if (echoed.algorithm() != authorized.algorithm()) {
            throw brokenEcho("connector echoed a %s digest but %s was authorized"
                    .formatted(echoed.algorithm().getCode(), authorized.algorithm().getCode()));
        }
        if (!echoed.hasLengthOfItsAlgorithm()) {
            throw brokenEcho("connector echoed a %d-byte digest, which %s never produces"
                    .formatted(echoed.length(), echoed.algorithm().getCode()));
        }
    }

    private static SigningEngineException brokenEcho(String defect) {
        return SigningEngineException
                .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, STEP, defect, null, BROKEN_ECHO_CLIENT_MESSAGE);
    }
}
