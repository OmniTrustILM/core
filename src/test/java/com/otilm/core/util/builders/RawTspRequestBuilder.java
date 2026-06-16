package com.otilm.core.util.builders;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

    /**
     * Emits a request carrying an <em>empty</em> {@code [0] IMPLICIT Extensions} block ({@code A0 00}).
     * {@code TimeStampRequestGenerator} can never produce this (it omits the tag when there are no
     * extensions), so the DER is assembled by hand. BouncyCastle deliberately accepts an empty
     * extensions SEQUENCE while parsing, which is why this otherwise-unreachable shape must be crafted
     * directly to exercise the parser's empty-extensions handling.
     */
    public byte[] buildWithEmptyExtensionsBlock() {
        var version = new ASN1Integer(1);
        var messageImprint = new DERSequence(new ASN1Encodable[]{
                new AlgorithmIdentifier(digestAlgorithmOid),
                new DEROctetString(hashedMessage)
        });
        var emptyExtensions = new DERTaggedObject(false, 0, new DERSequence());
        var timeStampReq = new DERSequence(new ASN1Encodable[]{version, messageImprint, emptyExtensions});
        try {
            return timeStampReq.getEncoded();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
