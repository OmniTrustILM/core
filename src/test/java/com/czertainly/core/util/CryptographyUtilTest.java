package com.czertainly.core.util;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.core.attribute.EcdsaSignatureAttributes;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CryptographyUtilTest {

    @BeforeAll
    static void registerProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    // --- resolveSignatureAlgorithmName: RSA ---

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void resolveRsaPkcs1AlgorithmName(DigestAlgorithm digest) {
        // given
        List<RequestAttributeV2> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                RsaSignatureAttributes.buildRequestDigest(digest)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals(digest.getProviderName() + "WITHRSA", result);
        assertFalse(result.contains("MGF1"));
    }

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void resolveRsaPssAlgorithmName(DigestAlgorithm digest) {
        // given
        List<RequestAttributeV2> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                RsaSignatureAttributes.buildRequestDigest(digest)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals(digest.getProviderName() + "WITHRSAANDMGF1", result);
    }

    @Test
    void resolveRsaSha256Pkcs1AlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals("SHA256WITHRSA", result);
    }

    @Test
    void resolveRsaSha256PssAlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals("SHA256WITHRSAANDMGF1", result);
    }

    // --- resolveSignatureAlgorithmName: ECDSA ---

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void resolveEcdsaAlgorithmName(DigestAlgorithm digest) {
        // given
        List<RequestAttributeV2> attrs = List.of(
                EcdsaSignatureAttributes.buildRequestDigest(digest)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertEquals(digest.getProviderName() + "WITHECDSA", result);
    }

    @Test
    void resolveEcdsaSha256AlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List.of(
                EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
        );

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertEquals("SHA256WITHECDSA", result);
    }

    // --- resolveSignatureAlgorithmName: FALCON ---

    @Test
    void resolveFalcon512AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_512, BouncyCastlePQCProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, publicKey, List.of());

        // then
        assertEquals("FALCON-512", result);
    }

    @Test
    void resolveFalcon1024AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_1024, BouncyCastlePQCProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, publicKey, List.of());

        // then
        assertEquals("FALCON-1024", result);
    }

    @Test
    void resolveFalconThrowsWhenInputIsNotValidAsn1() {
        // given
        String invalidKey = Base64.getEncoder().encodeToString(new byte[]{0x01, 0x02, 0x03});

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, invalidKey, List.of()));
    }

    @Test
    void resolveFalconThrowsWhenSpkiAlgorithmOidDoesNotMatch() throws Exception {
        // given — valid SPKI structure but ML-DSA key content handed to FALCON resolver
        String mlDsaKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_44, BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, mlDsaKey, List.of()));
    }

    // --- resolveSignatureAlgorithmName: ML-DSA ---

    @Test
    void resolveMlDsa44AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_44, BouncyCastleProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, publicKey, List.of());

        // then
        assertEquals(MLDSAParameterSpec.ml_dsa_44.getName(), result);
    }

    @Test
    void resolveMlDsa65AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_65, BouncyCastleProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, publicKey, List.of());

        // then
        assertEquals(MLDSAParameterSpec.ml_dsa_65.getName(), result);
    }

    @Test
    void resolveMlDsaThrowsWhenInputIsNotValidAsn1() {
        // given
        String invalidKey = Base64.getEncoder().encodeToString(new byte[]{0x01, 0x02, 0x03});

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, invalidKey, List.of()));
    }

    @Test
    void resolveMlDsaThrowsWhenSpkiAlgorithmOidDoesNotMatch() throws Exception {
        // given — valid SPKI structure but SLH-DSA key content handed to ML-DSA resolver
        String slhDsaKey = generatePublicKeyBase64("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s, BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, slhDsaKey, List.of()));
    }

    @Test
    void resolveMlDsaThrowsWhenKeyPayloadIsCorrupted() throws Exception {
        // given — correct ML-DSA OID but zeroed payload; BCMLDSAPublicKey validates key length and throws
        String corruptKey = buildSpkiWithGarbagePayload("ML-DSA", MLDSAParameterSpec.ml_dsa_44, BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, corruptKey, List.of()));
    }

    // --- resolveSignatureAlgorithmName: SLH-DSA ---

    @Test
    void resolveSlhDsaShake128sAlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s, BouncyCastleProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.SLHDSA, publicKey, List.of());

        // then
        assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), result);
    }

    @Test
    void resolveSlhDsaThrowsWhenInputIsNotValidAsn1() {
        // given
        String invalidKey = Base64.getEncoder().encodeToString(new byte[]{0x01, 0x02, 0x03});

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.SLHDSA, invalidKey, List.of()));
    }

    @Test
    void resolveSlhDsaThrowsWhenSpkiAlgorithmOidDoesNotMatch() throws Exception {
        // given — valid SPKI structure but Falcon key content handed to SLH-DSA resolver
        String falconKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_512, BouncyCastlePQCProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.SLHDSA, falconKey, List.of()));
    }

    // --- resolveSignatureAlgorithmName: unsupported algorithm ---

    @Test
    void resolveUnsupportedAlgorithmThrows() {
        // given
        KeyAlgorithm unsupported = KeyAlgorithm.MLKEM;

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(unsupported, null, List.of()));
    }

    // --- prepareSignatureAlgorithm ---

    @Test
    void prepareSignatureAlgorithmRsaSha256Pkcs1() {
        // given
        List<RequestAttribute> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
        );

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.RSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    @Test
    void prepareSignatureAlgorithmRsaSha512Pss() {
        // given
        List<RequestAttribute> attrs = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_512)
        );

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.RSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    @Test
    void prepareSignatureAlgorithmEcdsaSha384() {
        // given
        List<RequestAttribute> attrs = List.of(
                EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384)
        );

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    // --- helpers ---

    private static String generatePublicKeyBase64(String keyAlgorithm, AlgorithmParameterSpec spec, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, provider);
        kpg.initialize(spec);
        return Base64.getEncoder().encodeToString(kpg.generateKeyPair().getPublic().getEncoded());
    }

    private static String buildSpkiWithGarbagePayload(String keyAlgorithm, AlgorithmParameterSpec spec, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, provider);
        kpg.initialize(spec);
        SubjectPublicKeyInfo realSpki = SubjectPublicKeyInfo.getInstance(kpg.generateKeyPair().getPublic().getEncoded());
        SubjectPublicKeyInfo corruptSpki = new SubjectPublicKeyInfo(realSpki.getAlgorithm(), new byte[32]);
        return Base64.getEncoder().encodeToString(corruptSpki.getEncoded());
    }
}
