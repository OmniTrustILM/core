package com.otilm.core.signing.tsa.formatter;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.CertificateChain;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Two-phase formatter for RFC 3161 TimeStampTokens.
 *
 * <p>Phase 1 — {@link #formatDtbs}: produces the DER-encoded SignedAttributes
 * (Data To Be Signed). The caller signs these bytes externally.
 *
 * <p>Phase 2 — {@link #formatSigningResponse}: receives the signature and
 * assembles the final TimeStampToken. Both phases are stateless — the same
 * parameters must be passed to both calls so phase 1 can be replayed.
 */
public interface SignatureFormatterClient {

    /**
     * Drives BouncyCastle's TimeStampTokenGenerator to capture the SignedAttributes
     * bytes and returns them as the DTBS.
     *
     * @param request              parsed TSP request
     * @param timestampingProfile  workflow configuration
     * @param serialNumber         unique serial number for the TSTInfo
     * @param genTime              generation time for the TSTInfo
     * @param certificateChain     signing certificate and its chain
     * @param signatureAlgorithm   algorithm the signer will use
     * @return DER-encoded SignedAttributes bytes to be signed
     * @throws TspException if BouncyCastle fails to build the draft token
     */
    byte[] formatDtbs(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile, BigInteger serialNumber,
                      Instant genTime, CertificateChain certificateChain,
                      SignatureAlgorithm signatureAlgorithm) throws TspException;

    /**
     * Replays phase 1, injects the real signature, and produces a valid TimeStampToken.
     *
     * @param request              parsed TSP request (same as passed to formatDtbs)
     * @param timestampingProfile  workflow configuration (same as passed to formatDtbs)
     * @param serialNumber         serial number (same as passed to formatDtbs)
     * @param genTime              generation time (same as passed to formatDtbs)
     * @param certificateChain     signing certificate and its chain
     * @param dtbs                 DTBS bytes returned by formatDtbs
     * @param signature            raw signature bytes from the signer
     * @param signatureAlgorithm   algorithm used by the signer (same as passed to formatDtbs)
     * @return fully assembled, verifiable TimeStampToken
     * @throws TspException if BouncyCastle fails to assemble the token
     */
    byte[] formatSigningResponse(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile,
                                 BigInteger serialNumber, Instant genTime, CertificateChain certificateChain,
                                 byte[] dtbs, byte[] signature,
                                 SignatureAlgorithm signatureAlgorithm) throws TspException;
}
