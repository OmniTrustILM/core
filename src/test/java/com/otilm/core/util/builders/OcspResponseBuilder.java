package com.otilm.core.util.builders;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Builds the response an OCSP responder gives to one request. By default it is successful and answers {@code good} for
 * the requested certificate, is valid from now with no next update, echoes the request nonce, and is signed by
 * {@code signer} without embedded certificates.
 */
public final class OcspResponseBuilder {

    private final OCSPReq request;

    private final KeyPair signer;

    private X509Certificate signerCertificate;

    private CertificateStatus status = CertificateStatus.GOOD;

    private BigInteger serialNumber;

    private X509Certificate issuer;

    private ASN1ObjectIdentifier hashAlgorithm;

    private Date thisUpdate = new Date();

    private Date nextUpdate;

    private Extension nonce;

    private OcspResponseBuilder(OCSPReq request, KeyPair signer) {
        this.request = request;
        this.signer = signer;
        this.nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    }

    public static OcspResponseBuilder anOcspResponse(OCSPReq request, KeyPair signer) {
        return new OcspResponseBuilder(request, signer);
    }

    public OcspResponseBuilder withSignerCertificate(X509Certificate signerCertificate) {
        this.signerCertificate = signerCertificate;
        return this;
    }

    public OcspResponseBuilder withStatus(CertificateStatus status) {
        this.status = status;
        return this;
    }

    public OcspResponseBuilder withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /** Answers for the requested serial number under this issuer's name and key hashes. */
    public OcspResponseBuilder withIssuer(X509Certificate issuer) {
        this.issuer = issuer;
        return this;
    }

    /** Labels the requested issuer hashes with this algorithm. */
    public OcspResponseBuilder withHashAlgorithm(ASN1ObjectIdentifier hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    public OcspResponseBuilder withThisUpdate(Date thisUpdate) {
        this.thisUpdate = thisUpdate;
        return this;
    }

    public OcspResponseBuilder withNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
        return this;
    }

    /** Returns this nonce instead of the request's; {@code null} returns none. */
    public OcspResponseBuilder withNonce(byte[] nonce) {
        this.nonce = nonce == null
                ? null
                : new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
        return this;
    }

    public OCSPResp build() {
        try {
            DigestCalculator sha1 = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
            BasicOCSPRespBuilder responseBuilder = new JcaBasicOCSPRespBuilder(signer.getPublic(), sha1);
            responseBuilder.addResponse(answeredCertificateId(sha1), status, thisUpdate, nextUpdate, null);
            if (nonce != null) {
                responseBuilder.setResponseExtensions(new Extensions(nonce));
            }
            String signatureAlgorithm = signer.getPublic() instanceof ECPublicKey ? "SHA256withECDSA" : "SHA256withRSA";
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signer.getPrivate());
            X509CertificateHolder[] embeddedCertificates = signerCertificate == null
                    ? new X509CertificateHolder[0]
                    : new X509CertificateHolder[]{new JcaX509CertificateHolder(signerCertificate)};
            return new OCSPRespBuilder()
                    .build(OCSPRespBuilder.SUCCESSFUL,
                            responseBuilder.build(contentSigner, embeddedCertificates, new Date()));
        } catch (OperatorCreationException | OCSPException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to build the OCSP response", e);
        }
    }

    private CertificateID answeredCertificateId(DigestCalculator sha1)
            throws OCSPException, CertificateEncodingException {
        CertificateID requested = request.getRequestList()[0].getCertID();
        BigInteger answeredSerialNumber = serialNumber == null ? requested.getSerialNumber() : serialNumber;
        if (issuer != null) {
            return new CertificateID(sha1, new JcaX509CertificateHolder(issuer), answeredSerialNumber);
        }
        CertID requestedId = requested.toASN1Primitive();
        AlgorithmIdentifier answeredHashAlgorithm = hashAlgorithm == null
                ? requestedId.getHashAlgorithm()
                : new AlgorithmIdentifier(hashAlgorithm);
        return new CertificateID(new CertID(answeredHashAlgorithm, requestedId.getIssuerNameHash(),
                requestedId.getIssuerKeyHash(), new ASN1Integer(answeredSerialNumber)));
    }
}
