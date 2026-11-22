package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.key.normalization.ExplicitCurveFixtures;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class KeyDescriberTest {

    @Nested
    class FromSpki {

        @Test
        void describesAnEcKeyByItsCurve_whenTheSpkiNamesP521() throws Exception {
            // given
            var spki = ecPublicKey("secp521r1").getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, "P-521", 521));
        }

        @Test
        void namesTheCurveByItsRegistryName_whenTheCurveIsBrainpool() throws Exception {
            // given
            var spki = ecPublicKey("brainpoolP256r1").getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, "brainpoolP256r1", 256));
        }

        @Test
        void sizesButLeavesUnnamed_whenTheCurveIsOutsideTheTable() throws Exception {
            // given
            var curveOutsideTheTable = "secp160r1";
            var spki = ecPublicKey(curveOutsideTheTable).getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, null, 160));
        }

        @Test
        void sizesTheKeyByItsField_whenTheCurveOrderOutgrowsTheField() throws Exception {
            // given
            var spki = ecPublicKey("secp224k1").getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, "secp224k1", 224));
        }

        @Test
        void sizesTheModulus_whenTheSpkiHoldsAnRsaKey() throws Exception {
            // given
            var spki = rsaPublicKey(2048).getEncoded();
            var lengthAConnectorGotWrong = 1024;

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, lengthAConnectorGotWrong);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, 2048));
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.key.description.KeyDescriberTest#rsaKeyOids")
        void describesAnRsaKeyByItsModulus_whenACertificateKeyOpensWithAnRsaOid(ASN1ObjectIdentifier oid)
                throws Exception {
            // given
            var spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), rsaPublicKeyStructure(2048)).getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, 2048));
        }

        @Test
        void classifiesTheKeyByItsOid_whenACertificateStatesNoAlgorithm() throws Exception {
            // given
            var spki = postQuantumPublicKey("ML-KEM-768").getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.MLKEM, "ML-KEM-768", 9472));
        }

        @Test
        void sizesThePublicHalfByItsParameterSet_whenTheKeyIsPostQuantum() throws Exception {
            // given
            var spki = postQuantumPublicKey("ML-DSA-65").getEncoded();

            // when
            DescribedKey described = describeSpki(spki, KeyType.PUBLIC_KEY, KeyAlgorithm.MLDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.MLDSA, "ML-DSA-65", 15616));
        }

        @Test
        void keepsTheStatement_whenTheSpkiIsUnreadable() {
            // given
            var notAnSpki = new byte[]{1, 2, 3};

            // when
            DescribedKey described = describeSpki(notAnSpki, KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, 3072);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, 3072));
        }
    }

    @Nested
    class FromIdentifier {

        @ParameterizedTest
        @MethodSource("com.otilm.core.key.description.KeyDescriberTest#postQuantumParameterSets")
        void describesThePrivateHalfByItsParameterSet_whenTheOidIsPostQuantum(ASN1ObjectIdentifier oid,
                KeyAlgorithm algorithm, String name, int privateKeyBits) {
            // given
            var identifier = new AlgorithmIdentifier(oid);

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(identifier, null), KeyType.PRIVATE_KEY, algorithm, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(algorithm, name, privateKeyBits));
        }

        @Test
        void takesTheStatedLength_whenTheRsaHalfCarriesNoModulus() {
            // given
            var identifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
            var statedLength = 4096;

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(identifier, null), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, statedLength);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, statedLength));
        }

        @Test
        void sizesTheModulus_whenAPrivateRsaHalfStatesAnotherLength() {
            // given
            var identifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
            var lengthAConnectorGotWrong = 4096;

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(identifier, 2048), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA,
                            lengthAConnectorGotWrong);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, 2048));
        }

        @Test
        void classifiesTheKeyAsRsa_whenTheOidIsRsaPss() {
            // given
            var rsaPss = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(rsaPss, 2048), KeyType.PUBLIC_KEY, KeyAlgorithm.UNKNOWN, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.RSA, null, 2048));
        }

        @Test
        void sizesButLeavesUnnamed_whenTheParametersAreExplicit() {
            // given
            var explicitP384 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    new X962Parameters(ECNamedCurveTable.getByName("secp384r1")));

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(explicitP384, null), KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, null, 384));
        }

        @Test
        void leavesTheCurveUnread_whenExplicitParametersArePastTheBound() {
            // given
            var pastTheBound = ExplicitCurveFixtures.madeUp(600, 600, BigInteger.ONE);
            var explicit = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    new X962Parameters(pastTheBound));

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(explicit, null), KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, null);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, null, null));
        }

        @Test
        void keepsTheStatedAlgorithmUnnamedAndUnsized_whenThePostQuantumOidIsOutsideTheTable() {
            // given
            var futureParameterSet = new AlgorithmIdentifier(NISTObjectIdentifiers.sigAlgs.branch("99"));

            // when
            DescribedKey described = KeyDescriber
                    .describe(new KeyParameters(futureParameterSet, null), KeyType.PRIVATE_KEY, KeyAlgorithm.MLDSA,
                            32256);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.MLDSA, null, null));
        }
    }

    @Nested
    class FromStatement {

        @Test
        void dropsTheLength_whenTheAlgorithmsParametersFixIt() {
            // given
            var lengthNoParameterConfirms = 512;

            // when
            DescribedKey described = KeyDescriber.fromStatement(KeyAlgorithm.ECDSA, lengthNoParameterConfirms);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.ECDSA, null, null));
        }

        @Test
        void keepsTheLength_whenTheKeyIsAes() {
            // given
            var statedLength = 256;

            // when
            DescribedKey described = KeyDescriber.fromStatement(KeyAlgorithm.AES, statedLength);

            // then
            assertThat(described).isEqualTo(new DescribedKey(KeyAlgorithm.AES, null, statedLength));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> postQuantumParameterSets() {
        return Stream
                .of(arguments(NISTObjectIdentifiers.id_ml_dsa_44, KeyAlgorithm.MLDSA, "ML-DSA-44", 20480),
                        arguments(NISTObjectIdentifiers.id_ml_dsa_87, KeyAlgorithm.MLDSA, "ML-DSA-87", 39168),
                        arguments(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, KeyAlgorithm.SLHDSA, "SLH-DSA-SHA2-128S",
                                512),
                        arguments(NISTObjectIdentifiers.id_slh_dsa_shake_256f, KeyAlgorithm.SLHDSA,
                                "SLH-DSA-SHAKE-256F", 1024),
                        arguments(NISTObjectIdentifiers.id_alg_ml_kem_512, KeyAlgorithm.MLKEM, "ML-KEM-512", 13056),
                        arguments(BCObjectIdentifiers.falcon_512, KeyAlgorithm.FALCON, "FALCON-512", 10248));
    }

    static Stream<Arguments> rsaKeyOids() {
        return Stream
                .of(arguments(named("RSASSA-PSS", PKCSObjectIdentifiers.id_RSASSA_PSS)),
                        arguments(named("RSAES-OAEP", PKCSObjectIdentifiers.id_RSAES_OAEP)),
                        arguments(named("id-ea-rsa", X509ObjectIdentifiers.id_ea_rsa)));
    }

    private static DescribedKey describeSpki(byte[] spki, KeyType half, KeyAlgorithm statedAlgorithm,
            Integer statedLength) {
        return KeyDescriber.describe(KeyParameters.ofSpki(spki).orElse(null), half, statedAlgorithm, statedLength);
    }

    private static PublicKey ecPublicKey(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair().getPublic();
    }

    private static PublicKey rsaPublicKey(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair().getPublic();
    }

    private static RSAPublicKey rsaPublicKeyStructure(int bits) throws Exception {
        return RSAPublicKey
                .getInstance(SubjectPublicKeyInfo.getInstance(rsaPublicKey(bits).getEncoded()).parsePublicKey());
    }

    private static PublicKey postQuantumPublicKey(String parameterSet) throws Exception {
        return KeyPairGenerator.getInstance(parameterSet, new BouncyCastleProvider()).generateKeyPair().getPublic();
    }
}
