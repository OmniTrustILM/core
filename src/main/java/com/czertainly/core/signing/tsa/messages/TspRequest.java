package com.czertainly.core.signing.tsa.messages;

import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.core.signing.tsa.validator.TspRequestValidator;
import org.bouncycastle.asn1.x509.Extensions;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Parsed RFC 3161 Timestamp Request.
 *
 * <p>Before this record reaches the TSA engine, {@link TspRequestValidator} has already checked:
 * <ul>
 *   <li>Extensions — the request contains no extensions (profiles do not currently allow them).</li>
 *   <li>Hash algorithm — on the profile's allowed-digest-algorithm list.</li>
 *   <li>Policy OID — if present, on the profile's allowed-policy-id list.</li>
 * </ul>
 * The engine is responsible for effective-policy selection (defaulting to the profile's
 * {@code defaultPolicyId} when the client omits one), serial-number generation, and token assembly.
 *
 * @param hashAlgorithm            hash algorithm used to produce {@code hashedMessage}
 * @param hashedMessage            the message digest to be timestamped
 * @param policy                   policy OID requested by the client, or {@code Optional.empty()} if not specified
 * @param nonce                    client-provided nonce, or {@code Optional.empty()} if not requested
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
