package com.otilm.core.signing.tsa.messages;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import org.bouncycastle.asn1.x509.Extensions;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Test builder for {@link TspRequest}.
 * Defaults produce a minimal valid request.
 */
public final class TspRequestBuilder {

    private DigestAlgorithm hashAlgorithm = DigestAlgorithm.SHA_256;
    /** 32 zero bytes — a structurally valid SHA-256 message imprint. */
    private byte[] hashedMessage = new byte[32];
    private Optional<String> policy = Optional.empty();
    private Optional<BigInteger> nonce = Optional.empty();
    private boolean includeSignerCertificate = false;
    private Extensions requestExtensions = null;

    public static TspRequestBuilder aTspRequest() {
        return new TspRequestBuilder();
    }

    public TspRequestBuilder hashAlgorithm(DigestAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    public TspRequestBuilder hashedMessage(byte[] hashedMessage) {
        this.hashedMessage = hashedMessage;
        return this;
    }

    public TspRequestBuilder policy(String policy) {
        this.policy = Optional.of(policy);
        return this;
    }

    public TspRequestBuilder nonce(BigInteger nonce) {
        this.nonce = Optional.of(nonce);
        return this;
    }

    public TspRequestBuilder includeSignerCertificate(boolean includeSignerCertificate) {
        this.includeSignerCertificate = includeSignerCertificate;
        return this;
    }

    public TspRequestBuilder requestExtensions(Extensions requestExtensions) {
        this.requestExtensions = requestExtensions;
        return this;
    }

    public TspRequest build() {
        return new TspRequest(hashAlgorithm, hashedMessage, policy, nonce, includeSignerCertificate, requestExtensions);
    }
}
