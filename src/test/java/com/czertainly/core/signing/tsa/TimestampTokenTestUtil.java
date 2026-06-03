package com.czertainly.core.signing.tsa;

import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.util.CertificateTestUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

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
        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate cert = CertificateTestUtil.createTimestampingCertificate(keyPair);

        var dcProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        DigestCalculator sha256Calculator = dcProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        var signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .build("SHA256withRSA", keyPair.getPrivate(), cert);
        var tokenGenerator = new TimeStampTokenGenerator(
                signerInfoGenerator, sha256Calculator, new ASN1ObjectIdentifier("1.2.3.4"));

        var tsReq = new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, new byte[32]);
        return new TokenWithCert(tokenGenerator.generate(tsReq, BigInteger.ONE, new Date()), cert);
    }

    public record TokenWithCert(TimeStampToken token, X509Certificate cert) {}
}
