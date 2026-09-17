package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.EcdsaSignatureAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.model.crypto.KeyMaterial;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CryptographyUtilTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("usageRestrictions")
    void getForbiddenUsages_combinesTypeAndAlgorithmRestrictions(KeyType type, KeyAlgorithm algorithm,
            Set<KeyUsage> prohibited) {
        // given
        Set<KeyUsage> expectedRestrictions = prohibited;

        // when
        List<KeyUsage> actualRestrictions = CryptographyUtil.getForbiddenUsages(type, algorithm);

        // then
        assertEquals(expectedRestrictions, Set.copyOf(actualRestrictions));
        assertEquals(expectedRestrictions.size(), actualRestrictions.size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fingerprintVectors")
    void calculateKeyFingerprint_hashesSerializedUtf8Material(KeyMaterial material, String expectedFingerprint) {
        // given
        KeyMaterial serializedMaterial = material;

        // when
        String fingerprint = CryptographyUtil.calculateKeyFingerprint(serializedMaterial);

        // then
        assertEquals(expectedFingerprint, fingerprint);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unavailableKeyMaterial")
    void calculateKeyFingerprint_returnsNull_forUnavailableMaterial(KeyMaterial material) {
        // given
        KeyMaterial unavailableMaterial = material;

        // when
        String fingerprint = CryptographyUtil.calculateKeyFingerprint(unavailableMaterial);

        // then
        assertNull(fingerprint);
    }

    private static Stream<Arguments> usageRestrictions() {
        return Stream
                .of(arguments(named("RSA private key", KeyType.PRIVATE_KEY), KeyAlgorithm.RSA,
                        Set.of(KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.WRAP)),
                        arguments(named("RSA public key", KeyType.PUBLIC_KEY), KeyAlgorithm.RSA,
                                Set.of(KeyUsage.SIGN, KeyUsage.DECRYPT, KeyUsage.UNWRAP)),
                        arguments(named("unrestricted secret key", KeyType.SECRET_KEY), KeyAlgorithm.UNKNOWN, Set.of()),
                        arguments(named("ECDSA private key combines overlapping restrictions", KeyType.PRIVATE_KEY),
                                KeyAlgorithm.ECDSA,
                                Set.of(KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.WRAP, KeyUsage.DECRYPT)),
                        arguments(named("ECDSA public key combines overlapping restrictions", KeyType.PUBLIC_KEY),
                                KeyAlgorithm.ECDSA,
                                Set.of(KeyUsage.SIGN, KeyUsage.DECRYPT, KeyUsage.UNWRAP, KeyUsage.ENCRYPT)),
                        arguments(named("algorithm restrictions alone", KeyType.SECRET_KEY), KeyAlgorithm.ECDSA,
                                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)));
    }

    private static Stream<Arguments> fingerprintVectors() {
        String serializedBase64 = "c2VjcmV0";
        String serializedBase64Fingerprint = "1c1185e02ff3e23b3e5a1c5bc86cf15d4126caa3dcde0fdb6e93adc4deec119e";
        String unicodeMaterial = "klíč 🔑";
        String unicodeFingerprint = "7adb4926a001095f4690fe51341c9ea13f0f5d16383cdc241134c48abc438bea";
        return Stream
                .of(arguments(named("serialized value is not base64 decoded",
                        new KeyMaterial(KeyFormat.SPKI, serializedBase64)), serializedBase64Fingerprint),
                        arguments(named("serialized value uses UTF-8", new KeyMaterial(KeyFormat.RAW, unicodeMaterial)),
                                unicodeFingerprint));
    }

    private static Stream<Arguments> unavailableKeyMaterial() {
        String serializedValue = "c2VjcmV0";
        return Stream
                .of(arguments(named("absent material", (KeyMaterial) null)),
                        arguments(named("absent format", new KeyMaterial(null, serializedValue))),
                        arguments(named("absent serialized value", new KeyMaterial(KeyFormat.SPKI, null))),
                        arguments(named("custom material", new KeyMaterial(KeyFormat.CUSTOM, serializedValue))));
    }

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
        List<RequestAttributeV2> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(digest));

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
        List<RequestAttributeV2> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(digest));

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals(digest.getProviderName() + "WITHRSAANDMGF1", result);
    }

    @Test
    void resolveRsaSha256Pkcs1AlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, null, attrs);

        // then
        assertEquals("SHA256WITHRSA", result);
    }

    @Test
    void resolveRsaSha256PssAlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

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
        List<RequestAttributeV2> attrs = List.of(EcdsaSignatureAttributes.buildRequestDigest(digest));

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertEquals(digest.getProviderName() + "WITHECDSA", result);
    }

    @Test
    void resolveEcdsaSha256AlgorithmName() {
        // given
        List<RequestAttributeV2> attrs = List.of(EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertEquals("SHA256WITHECDSA", result);
    }

    // --- resolveSignatureAlgorithmName: FALCON ---

    @Test
    void resolveFalcon512AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_512,
                BouncyCastlePQCProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, publicKey, List.of());

        // then
        assertEquals("FALCON-512", result);
    }

    @Test
    void resolveFalcon1024AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_1024,
                BouncyCastlePQCProvider.PROVIDER_NAME);

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
        String mlDsaKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, mlDsaKey, List.of()));
    }

    // --- resolveSignatureAlgorithmName: ML-DSA ---

    @Test
    void resolveMlDsa44AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                BouncyCastleProvider.PROVIDER_NAME);

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, publicKey, List.of());

        // then
        assertEquals(MLDSAParameterSpec.ml_dsa_44.getName(), result);
    }

    @Test
    void resolveMlDsa65AlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_65,
                BouncyCastleProvider.PROVIDER_NAME);

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
        String slhDsaKey = generatePublicKeyBase64("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s,
                BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, slhDsaKey, List.of()));
    }

    @Test
    void resolveMlDsaThrowsWhenKeyPayloadIsCorrupted() throws Exception {
        // given — correct ML-DSA OID but zeroed payload; BCMLDSAPublicKey validates key length and throws
        String corruptKey = buildSpkiWithGarbagePayload("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                BouncyCastleProvider.PROVIDER_NAME);

        // when + then
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, corruptKey, List.of()));
    }

    // --- resolveSignatureAlgorithmName: SLH-DSA ---

    @Test
    void resolveSlhDsaShake128sAlgorithmName() throws Exception {
        // given
        String publicKey = generatePublicKeyBase64("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s,
                BouncyCastleProvider.PROVIDER_NAME);

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
        String falconKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_512,
                BouncyCastlePQCProvider.PROVIDER_NAME);

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

    // --- resolveSignatureAlgorithmName: precomputed-PQC-spec overload ---

    @Test
    void resolveWithPrecomputedSpec_rsa_resolvesFromAttributes_ignoringSpec() {
        // given
        List<RequestAttributeV2> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when — the precomputed PQC spec is irrelevant for classical algorithms
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.RSA, attrs, "ignored-spec");

        // then
        assertEquals("SHA256WITHRSA", result);
    }

    @Test
    void resolveWithPrecomputedSpec_ecdsa_resolvesFromAttributes_ignoringSpec() {
        // given
        List<RequestAttributeV2> attrs = List.of(EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384));

        // when
        String result = CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.ECDSA, attrs, "ignored-spec");

        // then
        assertEquals("SHA384WITHECDSA", result);
    }

    @Test
    void resolveWithPrecomputedSpec_pqc_returnsSpecVerbatim_withoutParsingPublicKey() {
        // given / when / then — for FALCON / ML-DSA / SLH-DSA the precomputed parameter-spec name is returned as-is
        assertEquals("FALCON-512",
                CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.FALCON, List.of(), "FALCON-512"));
        assertEquals(MLDSAParameterSpec.ml_dsa_65.getName(), CryptographyUtil
                .resolveSignatureAlgorithmName(KeyAlgorithm.MLDSA, List.of(), MLDSAParameterSpec.ml_dsa_65.getName()));
        assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(),
                CryptographyUtil
                        .resolveSignatureAlgorithmName(KeyAlgorithm.SLHDSA, List.of(),
                                SLHDSAParameterSpec.slh_dsa_shake_128s.getName()));
    }

    @Test
    void resolveWithPrecomputedSpec_unsupportedAlgorithm_throws() {
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolveSignatureAlgorithmName(KeyAlgorithm.MLKEM, List.of(), null));
    }

    // --- prepareSignatureAlgorithm ---

    @Test
    void prepareSignatureAlgorithmRsaSha256Pkcs1() {
        // given
        List<RequestAttribute> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.RSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    @Test
    void prepareSignatureAlgorithmRsaSha512Pss() {
        // given
        List<RequestAttribute> attrs = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_512));

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.RSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    @Test
    void prepareSignatureAlgorithmEcdsaSha384() {
        // given
        List<RequestAttribute> attrs = List.of(EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384));

        // when
        AlgorithmIdentifier algId = CryptographyUtil.prepareSignatureAlgorithm(KeyAlgorithm.ECDSA, null, attrs);

        // then
        assertNotNull(algId);
        assertNotNull(algId.getAlgorithm());
    }

    // --- resolvePqcParameterSpecName ---

    @Test
    void resolvePqcSpecNameReturnsNullForRsa() {
        assertNull(CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.RSA, null));
    }

    @Test
    void resolvePqcSpecNameReturnsNullForEcdsa() {
        assertNull(CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.ECDSA, null));
    }

    @Test
    void resolvePqcSpecNameReturnsNullForMlkem() {
        assertNull(CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.MLKEM, null));
    }

    @Test
    void resolvePqcSpecNameFalcon1024() throws Exception {
        String publicKey = generatePublicKeyBase64("Falcon", FalconParameterSpec.falcon_1024,
                BouncyCastlePQCProvider.PROVIDER_NAME);
        assertEquals("FALCON-1024", CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.FALCON, publicKey));
    }

    @Test
    void resolvePqcSpecNameMlDsa44() throws Exception {
        String publicKey = generatePublicKeyBase64("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                BouncyCastleProvider.PROVIDER_NAME);
        assertEquals(MLDSAParameterSpec.ml_dsa_44.getName(),
                CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.MLDSA, publicKey));
    }

    @Test
    void resolvePqcSpecNameSlhDsa() throws Exception {
        String publicKey = generatePublicKeyBase64("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s,
                BouncyCastleProvider.PROVIDER_NAME);
        assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(),
                CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.SLHDSA, publicKey));
    }

    @Test
    void resolvePqcSpecNameThrowsOnInvalidPqcKey() {
        String invalidKey = Base64.getEncoder().encodeToString(new byte[]{0x01, 0x02, 0x03});
        assertThrows(ValidationException.class,
                () -> CryptographyUtil.resolvePqcParameterSpecName(KeyAlgorithm.MLDSA, invalidKey));
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
        SubjectPublicKeyInfo realSpki = SubjectPublicKeyInfo
                .getInstance(kpg.generateKeyPair().getPublic().getEncoded());
        SubjectPublicKeyInfo corruptSpki = new SubjectPublicKeyInfo(realSpki.getAlgorithm(), new byte[32]);
        return Base64.getEncoder().encodeToString(corruptSpki.getEncoded());
    }
}
