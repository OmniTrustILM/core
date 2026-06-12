package com.otilm.core.util.builders;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds DER-encoded RFC 3161 timestamp-request bytes. Defaults produce a minimal, valid
 * SHA-256 request; callers override only the field that drives the scenario under test.
 */
public final class RawTspRequestBuilder {

    private record RawExtension(String oid, byte[] value) {
    }

    private ASN1ObjectIdentifier digestAlgorithmOid = TSPAlgorithms.SHA256;
    private byte[] hashedMessage = new byte[32];
    private BigInteger nonce = null;
    private String policyOid = null;
    private boolean certReq = false;
    private final List<RawExtension> extensions = new ArrayList<>();

    public static RawTspRequestBuilder aRawTspRequest() {
        return new RawTspRequestBuilder();
    }

    public RawTspRequestBuilder withDigestAlgorithmOid(ASN1ObjectIdentifier oid) {
        this.digestAlgorithmOid = oid;
        return this;
    }

    public RawTspRequestBuilder withHashedMessage(byte[] hashedMessage) {
        this.hashedMessage = hashedMessage;
        return this;
    }

    public RawTspRequestBuilder withNonce(BigInteger nonce) {
        this.nonce = nonce;
        return this;
    }

    public RawTspRequestBuilder withPolicyOid(String policyOid) {
        this.policyOid = policyOid;
        return this;
    }

    public RawTspRequestBuilder withCertReq(boolean certReq) {
        this.certReq = certReq;
        return this;
    }

    public RawTspRequestBuilder withExtension(String oid, byte[] value) {
        this.extensions.add(new RawExtension(oid, value));
        return this;
    }

    public byte[] build() {
        var generator = new TimeStampRequestGenerator();
        generator.setCertReq(certReq);
        if (policyOid != null) {
            generator.setReqPolicy(new ASN1ObjectIdentifier(policyOid));
        }
        for (RawExtension extension : extensions) {
            generator.addExtension(new ASN1ObjectIdentifier(extension.oid()), false, extension.value());
        }
        try {
            var request = nonce != null
                    ? generator.generate(digestAlgorithmOid, hashedMessage, nonce)
                    : generator.generate(digestAlgorithmOid, hashedMessage);
            return request.getEncoded();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
