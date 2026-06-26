package com.otilm.core.signing.tsa;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.util.CertificateTestUtil;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Test utilities for generating RFC 3161 {@link TimeStampToken} bytes
 * without a live signing connector.
 */
public final class TimestampTokenTestUtil {

    private TimestampTokenTestUtil() {
    }

    /**
     * Generates a minimal, parseable {@link TimeStampToken}.
     * Uses an RSA key pair and a self-signed TSA certificate created via the standard test utilities.
     */
    public static TimeStampToken createTimestampToken() throws Exception {
        return createTimestampTokenWithCert().token();
    }

    /**
     * Generates a minimal {@link TimeStampToken} together with the {@link X509Certificate} that was
     * used to sign it, so callers can build a matching {@link CertificateChain} for signature
     * verification tests.
     */
    public static TokenWithCert createTimestampTokenWithCert() throws Exception {
        ensureBouncyCastleProvider();
        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate cert = CertificateTestUtil.createTimestampingCertificate(keyPair);

        var dcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        DigestCalculator sha256Calculator = dcProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        var signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build("SHA256withRSA", keyPair.getPrivate(), cert);
        var tokenGenerator = new TimeStampTokenGenerator(
                signerInfoGenerator, sha256Calculator, new ASN1ObjectIdentifier("1.2.3.4"));

        var tsReq = new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, new byte[32]);
        return new TokenWithCert(tokenGenerator.generate(tsReq, BigInteger.ONE, new Date()), cert);
    }

    // ── External-signature token assembly ─────────────────────────────────────
    //
    // The three helpers below implement the signature-formatting connector's side of the two-round-trip
    // RFC 3161 contract: phase 1 produces the exact CMS data-to-be-signed (the DER SignedAttributes over
    // a TSTInfo), an external signer signs those bytes, and phase 2 embeds the external signature into a
    // CMS SignedData without ever holding the private key. Phase consistency relies on buildTstInfo being
    // deterministic for the same inputs, which both phases receive in their request DTOs.

    /**
     * Builds the DER-encoded RFC 3161 {@code TSTInfo} from the timestamping request fields.
     * Deterministic: the same inputs always produce the same bytes.
     */
    public static byte[] buildTstInfo(String policyOid,
                                      String hashAlgorithmOid,
                                      byte[] hashedMessage,
                                      BigInteger serialNumber,
                                      Instant genTime,
                                      BigInteger nonce) throws Exception {
        MessageImprint messageImprint = new MessageImprint(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgorithmOid)), hashedMessage);
        TSTInfo tstInfo = new TSTInfo(
                new ASN1ObjectIdentifier(policyOid),
                messageImprint,
                new ASN1Integer(serialNumber),
                new ASN1GeneralizedTime(Date.from(genTime)),
                null,
                ASN1Boolean.FALSE,
                nonce == null ? null : new ASN1Integer(nonce),
                null,
                null);
        return tstInfo.getEncoded(ASN1Encoding.DER);
    }

    /**
     * Produces the CMS data-to-be-signed for a TSTInfo: the DER-encoded {@code SignedAttributes} set
     * carrying contentType, messageDigest (digest of the TSTInfo with {@code digestAlgorithm}) and the
     * signingCertificateV2 reference RFC 3161 requires. A CMS signature over exactly these bytes embeds
     * verifiably via {@link #assembleTimestampToken}.
     */
    public static byte[] buildSignedAttributesDtbs(byte[] tstInfoDer,
                                                   byte[] signerCertificateDer,
                                                   AlgorithmIdentifier digestAlgorithm) throws Exception {
        ensureBouncyCastleProvider();
        byte[] tstInfoDigest = digest(digestAlgorithm, tstInfoDer);
        byte[] signerCertSha256 = digest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), signerCertificateDer);

        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.id_ct_TSTInfo)));
        attributes.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(tstInfoDigest))));
        attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(new ESSCertIDv2(signerCertSha256)))));
        return new DERSet(attributes).getEncoded(ASN1Encoding.DER);
    }

    /**
     * Assembles a DER-encoded {@code TimeStampToken} (CMS {@code SignedData} over the TSTInfo) from an
     * <em>externally produced</em> signature: {@code signature} must be a {@code signatureAlgorithm}
     * signature over exactly {@code dtbs} (the output of {@link #buildSignedAttributesDtbs}), made with
     * the private key matching the first certificate of {@code certificateChainDer}.
     */
    public static byte[] assembleTimestampToken(byte[] dtbs,
                                                byte[] signature,
                                                SignatureAlgorithm signatureAlgorithm,
                                                List<byte[]> certificateChainDer,
                                                byte[] tstInfoDer,
                                                boolean includeCertificates) throws Exception {
        ASN1Set signedAttributes = ASN1Set.getInstance(ASN1Primitive.fromByteArray(dtbs));

        X509CertificateHolder signerCertificate = new X509CertificateHolder(certificateChainDer.getFirst());
        SignerInfo signerInfo = new SignerInfo(
                new SignerIdentifier(new IssuerAndSerialNumber(signerCertificate.getIssuer(), signerCertificate.getSerialNumber())),
                signatureAlgorithm.getDigestAlgorithmIdentifier(),
                signedAttributes,
                signatureAlgorithm.getAlgorithmIdentifier(),
                new DEROctetString(signature),
                null);

        DERSet certificates = null;
        if (includeCertificates) {
            ASN1EncodableVector certificateVector = new ASN1EncodableVector();
            for (byte[] certificateDer : certificateChainDer) {
                certificateVector.add(new X509CertificateHolder(certificateDer).toASN1Structure());
            }
            certificates = new DERSet(certificateVector);
        }

        SignedData signedData = new SignedData(
                new DERSet(signatureAlgorithm.getDigestAlgorithmIdentifier()),
                new ContentInfo(PKCSObjectIdentifiers.id_ct_TSTInfo, new DEROctetString(tstInfoDer)),
                certificates,
                null,
                new DERSet(signerInfo));
        return new ContentInfo(PKCSObjectIdentifiers.signedData, signedData).getEncoded(ASN1Encoding.DER);
    }

    private static byte[] digest(AlgorithmIdentifier digestAlgorithm, byte[] data) throws Exception {
        return MessageDigest.getInstance(digestAlgorithm.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME)
                .digest(data);
    }

    private static void ensureBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public record TokenWithCert(TimeStampToken token, X509Certificate cert) {}
}
