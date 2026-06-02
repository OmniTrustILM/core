package com.czertainly.core.signing.tsa.messages;

import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import org.bouncycastle.asn1.x509.Extensions;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Parsed RFC3161 Timestamp Request.
 *
 * <p>The request validation (extensions, hash algorithm, hash length) and policy resolution
 * are performed by the layer above the engine before constructing this record.
 *
 * @param hashAlgorithm            hash algorithm used to produce {@code hashedMessage}
 * @param hashedMessage            the message digest to be timestamped
 * @param policy                   the already-resolved policy including worker and signature algorithm
 * @param nonce                    client-provided nonce to include in the response, or {@code null} if not requested
 * @param includeSignerCertificate whether to embed the signer certificate in the response
 * @param requestExtensions        validated extensions from the client request, or {@code null} if none
 */
public record TspRequest(
        DigestAlgorithm hashAlgorithm,
        byte[] hashedMessage,
        Optional<String> policy,
        Optional<BigInteger> nonce,
        boolean includeSignerCertificate,
        Extensions requestExtensions) {
}
