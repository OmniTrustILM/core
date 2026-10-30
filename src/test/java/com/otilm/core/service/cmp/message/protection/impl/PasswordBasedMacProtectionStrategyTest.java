package com.otilm.core.service.cmp.message.protection.impl;

import java.security.Security;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link PasswordBasedMacProtectionStrategy}.
 *
 * <p>
 * Regression coverage: when a CMP profile has {@code Response Protection Method = sharedSecret} and the incoming
 * request is <em>not</em> PBM-protected (signature- or DH-based), the response PBM strategy is still built from the
 * request's protection algorithm. That algorithm carries no {@link PBMParameter}, so the strategy must fall back to
 * platform defaults (SHA-256 / HMAC-SHA256) instead of dereferencing a {@code null} {@code PBMParameter} and throwing
 * an NPE.
 * </p>
 */
class PasswordBasedMacProtectionStrategyTest {

    private static final ASN1ObjectIdentifier ECDSA_WITH_SHA384 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
    private static final ASN1ObjectIdentifier SHA1_OWF = new ASN1ObjectIdentifier("1.3.14.3.2.26");
    private static final ASN1ObjectIdentifier HMAC_SHA1 = new ASN1ObjectIdentifier("1.2.840.113549.2.7");

    private static final byte[] SHARED_SECRET = "shared-secret-value".getBytes();
    private static final byte[] SALT = "0123456789012345678901234".getBytes();
    private static final int ITERATION_COUNT = 1000;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void buildsWithDefaultAlgorithms_whenRequestUsesSignatureAlgorithmWithoutParameters() throws Exception {
        // given: an ECDSA signature algorithm identifier with no parameters (getParameters() == null),
        // which is exactly what a signature-protected KUR carries — no PBMParameter to echo
        AlgorithmIdentifier signatureAlg = new AlgorithmIdentifier(ECDSA_WITH_SHA384);

        // when / then: constructing the PBM response strategy must not throw an NPE
        PasswordBasedMacProtectionStrategy strategy = new PasswordBasedMacProtectionStrategy(null, signatureAlg,
                SHARED_SECRET, SALT, ITERATION_COUNT);

        // and: the produced protection uses the platform default digest (SHA-256) and MAC (HMAC-SHA256)
        assertThat(strategy.getProtectionAlg().getAlgorithm()).isEqualTo(CMPObjectIdentifiers.passwordBasedMac);
        PBMParameter produced = PBMParameter.getInstance(strategy.getProtectionAlg().getParameters());
        assertThat(produced.getOwf().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_sha256);
        assertThat(produced.getMac().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_hmacWithSHA256);
    }

    @Test
    void buildsWithDefaultAlgorithms_whenRequestUsesSignatureAlgorithmWithNullParameters() {
        // given: an RSA signature algorithm identifier whose parameters are ASN.1 NULL (not a PBMParameter sequence)
        AlgorithmIdentifier signatureAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption,
                DERNull.INSTANCE);

        // when / then: constructing the PBM response strategy must not throw (pre-fix: IllegalArgumentException)
        assertThatCode(
                () -> new PasswordBasedMacProtectionStrategy(null, signatureAlg, SHARED_SECRET, SALT, ITERATION_COUNT))
                .doesNotThrowAnyException();
    }

    @Test
    void echoesRequestAlgorithms_whenRequestIsPbmProtected() throws Exception {
        // given: a genuine PBM protection algorithm carrying SHA1 owf + HMAC-SHA1 mac
        AlgorithmIdentifier pbmAlg = new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, new PBMParameter(
                SALT, new AlgorithmIdentifier(SHA1_OWF), ITERATION_COUNT, new AlgorithmIdentifier(HMAC_SHA1)));

        // when
        PasswordBasedMacProtectionStrategy strategy = new PasswordBasedMacProtectionStrategy(null, pbmAlg,
                SHARED_SECRET, SALT, ITERATION_COUNT);

        // then: the client's chosen digest/mac are echoed, not overridden by the defaults
        PBMParameter produced = PBMParameter.getInstance(strategy.getProtectionAlg().getParameters());
        assertThat(produced.getOwf().getAlgorithm()).isEqualTo(SHA1_OWF);
        assertThat(produced.getMac().getAlgorithm()).isEqualTo(HMAC_SHA1);
    }
}
