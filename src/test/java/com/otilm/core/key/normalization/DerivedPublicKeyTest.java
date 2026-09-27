package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.stream.Stream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class DerivedPublicKeyTest {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @ParameterizedTest
    @MethodSource("platformKeys")
    void of_namesTheAlgorithmAndDerivesThePublicKeyAConnectorReturns(KeyPair keyPair, KeyAlgorithm algorithm) {
        // when
        DerivedPublicKey derived = DerivedPublicKey.of(PrivateKeyInfo.getInstance(KeyFiles.pkcs8(keyPair)));

        // then
        assertThat(derived.algorithm()).isEqualTo(algorithm);
        assertThat(derived.publicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    void of_derivesThePublicKeyRatherThanTakingTheOneTheFileStates() throws Exception {
        // given
        KeyPair keyPair = KeyFiles.ec();
        byte[] anotherPublicKey = SubjectPublicKeyInfo
                .getInstance(KeyFiles.ec().getPublic().getEncoded())
                .getPublicKeyData()
                .getOctets();
        PrivateKeyInfo stated = PrivateKeyInfo.getInstance(KeyFiles.pkcs8(keyPair));
        PrivateKeyInfo statingAnotherPublicKey = new PrivateKeyInfo(stated.getPrivateKeyAlgorithm(),
                stated.parsePrivateKey(), null, anotherPublicKey);

        // when
        DerivedPublicKey derived = DerivedPublicKey.of(statingAnotherPublicKey);

        // then
        assertThat(derived.publicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    void of_refusesAKeyOfAnAlgorithmThePlatformDoesNotHold() throws Exception {
        // given
        PrivateKeyInfo ed25519 = PrivateKeyInfo.getInstance(KeyFiles.pkcs8(KeyFiles.keyPair("Ed25519", null, BC)));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> DerivedPublicKey.of(ed25519));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNSUPPORTED_ALGORITHM.formatted("1.3.101.112"));
    }

    @Test
    void of_refusesAnRsaKeyWithoutThePublicExponentAsUnreadable() throws Exception {
        // given
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) KeyFiles.rsa().getPrivate();
        PrivateKeyInfo withoutPublicExponent = PrivateKeyInfo
                .getInstance(KeyFactory
                        .getInstance("RSA", BC)
                        .generatePrivate(new RSAPrivateKeySpec(key.getModulus(), key.getPrivateExponent()))
                        .getEncoded());

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> DerivedPublicKey.of(withoutPublicExponent));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void of_refusesAKeyWhosePayloadNestsDeeperThanAKeyFileMay() throws Exception {
        // given
        PrivateKeyInfo deep = KeyFiles
                .privateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                        KeyFiles.nested(KeyFileReader.MAXIMUM_NESTING_DEPTH + 1));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> DerivedPublicKey.of(deep));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("nesting depth", 32));
    }

    @ParameterizedTest
    @MethodSource("platformAlgorithms")
    void of_refusesADamagedKeyOfAPlatformAlgorithmAsUnreadable(AlgorithmIdentifier algorithm) {
        // given
        PrivateKeyInfo damaged = KeyFiles.privateKeyInfo(algorithm, new byte[]{1, 2, 3});

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> DerivedPublicKey.of(damaged));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void of_refusesAnRsaKeyWithAnEvenPublicExponentAsUnreadable() throws Exception {
        // given
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) KeyFiles.rsa().getPrivate();
        PrivateKeyInfo evenExponent = PrivateKeyInfo
                .getInstance(KeyFactory
                        .getInstance("RSA", BC)
                        .generatePrivate(new RSAPrivateCrtKeySpec(key.getModulus(), BigInteger.valueOf(65_536),
                                key.getPrivateExponent(), key.getPrimeP(), key.getPrimeQ(), key.getPrimeExponentP(),
                                key.getPrimeExponentQ(), key.getCrtCoefficient()))
                        .getEncoded());

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> DerivedPublicKey.of(evenExponent));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    static Stream<Named<AlgorithmIdentifier>> platformAlgorithms() {
        return Stream
                .of(named("RSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)),
                        named("EC",
                                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                                        X9ObjectIdentifiers.prime256v1)),
                        named("ML-DSA", new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44)),
                        named("SLH-DSA", new AlgorithmIdentifier(NISTObjectIdentifiers.id_slh_dsa_sha2_128f)),
                        named("ML-KEM", new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512)),
                        named("Falcon", new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512)));
    }

    static Stream<Arguments> platformKeys() throws Exception {
        return Stream
                .of(arguments(named("RSA", KeyFiles.rsa()), KeyAlgorithm.RSA),
                        arguments(named("EC P-256", KeyFiles.ec()), KeyAlgorithm.ECDSA),
                        arguments(
                                named("EC P-384 from another provider",
                                        KeyFiles.keyPair("EC", new ECGenParameterSpec("secp384r1"), "SunEC")),
                                KeyAlgorithm.ECDSA),
                        arguments(named("ML-DSA-44", KeyFiles.keyPair("ML-DSA", MLDSAParameterSpec.ml_dsa_44, BC)),
                                KeyAlgorithm.MLDSA),
                        arguments(
                                named("HashML-DSA-44",
                                        KeyFiles.keyPair("HASH-ML-DSA", MLDSAParameterSpec.ml_dsa_44_with_sha512, BC)),
                                KeyAlgorithm.MLDSA),
                        arguments(
                                named("SLH-DSA-SHA2-128F",
                                        KeyFiles.keyPair("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, BC)),
                                KeyAlgorithm.SLHDSA),
                        arguments(
                                named("HashSLH-DSA-SHA2-128F",
                                        KeyFiles
                                                .keyPair("HASH-SLH-DSA",
                                                        SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256, BC)),
                                KeyAlgorithm.SLHDSA),
                        arguments(named("ML-KEM-512", KeyFiles.keyPair("ML-KEM", MLKEMParameterSpec.ml_kem_512, BC)),
                                KeyAlgorithm.MLKEM),
                        arguments(named("Falcon-512",
                                KeyFiles
                                        .keyPair("FALCON", FalconParameterSpec.falcon_512,
                                                BouncyCastlePQCProvider.PROVIDER_NAME)),
                                KeyAlgorithm.FALCON));
    }
}
