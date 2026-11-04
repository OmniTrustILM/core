package com.otilm.core.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.SignatureVerificationBoundsFixtures.compositeSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.pssSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.rsaPublicKeyInfo;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class SignatureVerificationBoundsTest {

    private static final BigInteger F4 = RSAKeyGenParameterSpec.F4;
    private static final byte[] UNUSABLE_BYTES = {1, 2, 3};
    private static final int ML_DSA_44_PUBLIC_KEY_BYTES = 1312;
    private static final int ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
    private static final int ED25519_PUBLIC_KEY_BYTES = 32;
    private static final String UNKNOWN_ALGORITHM_OID = "1.2.3.4";
    private static final String SUBJECT = "CN=device-1";

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── RequireSupportedPublicKey ─────────────────────────────────────────────

    @Nested
    class RequireSupportedPublicKey {

        @ParameterizedTest(name = "{0}")
        @MethodSource({"rsaKeysBeyondTheCaps", "compositeKeys", "keysOfAnUnsupportedAlgorithm"})
        void refuses_whenKeyIsNotOneThatCoreBuilds(SubjectPublicKeyInfo publicKey) {
            // given — a key of an algorithm that is not supported, or an RSA key beyond the caps

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds.requireSupportedPublicKey(publicKey);

            // then
            assertThatThrownBy(require).isInstanceOf(InvalidKeyException.class);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource({
                "rsaKeysWithinTheCaps",
                "keysOfASupportedAlgorithm",
                "keysOfEveryListedAlgorithm",
                "rsaKeysThatCannotBeRead"})
        void accepts_whenKeyIsOfASupportedAlgorithmWithinTheCaps(SubjectPublicKeyInfo publicKey) {
            // given — a key of a supported algorithm, an RSA key within the caps or one that no key builder builds

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds.requireSupportedPublicKey(publicKey);

            // then
            assertThatCode(require).doesNotThrowAnyException();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<SubjectPublicKeyInfo>> rsaKeysBeyondTheCaps() throws Exception {
            ASN1ObjectIdentifier rsaEncryption = PKCSObjectIdentifiers.rsaEncryption;
            BigInteger twoToThe256 = BigInteger.ONE.shiftLeft(256);
            return Stream
                    .of(named("an RSA modulus of 16384 bits", rsaPublicKeyInfo(rsaEncryption, 16384, F4)),
                            named("an RSA modulus of 8193 bits, one over the cap",
                                    rsaPublicKeyInfo(rsaEncryption, 8193, F4)),
                            named("an RSA public exponent of 2^256",
                                    rsaPublicKeyInfo(rsaEncryption, 2048, twoToThe256)),
                            named("an RSASSA-PSS key with a modulus of 16384 bits",
                                    rsaPublicKeyInfo(PKCSObjectIdentifiers.id_RSASSA_PSS, 16384, F4)));
        }

        static Stream<Named<SubjectPublicKeyInfo>> compositeKeys() throws Exception {
            SubjectPublicKeyInfo rsaKeyOf16384Bits = rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);
            byte[] rsaKey = rsaKeyOf16384Bits.getPublicKeyData().getOctets();
            DERSequence components = new DERSequence(rsaKeyOf16384Bits);
            // a composite key of a specific algorithm is its first component followed by the second
            byte[] mlDsa44AndRsa = concatenated(new byte[ML_DSA_44_PUBLIC_KEY_BYTES], rsaKey);
            byte[] mlDsa44AndEd25519 = concatenated(new byte[ML_DSA_44_PUBLIC_KEY_BYTES],
                    new byte[ED25519_PUBLIC_KEY_BYTES]);
            byte[] mlKem768AndRsa = concatenated(new byte[ML_KEM_768_PUBLIC_KEY_BYTES], rsaKey);
            return Stream
                    .of(named("a generic composite key with an RSA component of 16384 bits",
                            new SubjectPublicKeyInfo(algorithm(MiscObjectIdentifiers.id_alg_composite), components)),
                            named("a generic composite key under the other generic identifier",
                                    new SubjectPublicKeyInfo(algorithm(MiscObjectIdentifiers.id_composite_key),
                                            components)),
                            named("a composite signature key with an RSA component, MLDSA44-RSA2048-PKCS15-SHA256",
                                    new SubjectPublicKeyInfo(
                                            algorithm(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256),
                                            mlDsa44AndRsa)),
                            named("a composite signature key without one, MLDSA44-Ed25519-SHA512",
                                    new SubjectPublicKeyInfo(algorithm(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512),
                                            mlDsa44AndEd25519)),
                            named("a composite KEM key with an RSA component, MLKEM768-RSA2048-SHA3-256",
                                    new SubjectPublicKeyInfo(
                                            algorithm(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256),
                                            mlKem768AndRsa)));
        }

        static Stream<Named<SubjectPublicKeyInfo>> keysOfAnUnsupportedAlgorithm() throws Exception {
            BigInteger prime = BigInteger.valueOf(23);
            byte[] ecPoint = SubjectPublicKeyInfo
                    .getInstance(ecKeyPair().getPublic().getEncoded())
                    .getPublicKeyData()
                    .getOctets();
            AlgorithmIdentifier diffieHellman = new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement,
                    new DHParameter(prime, BigInteger.valueOf(5), 0));
            AlgorithmIdentifier dsa = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                    new DSAParameter(prime, BigInteger.valueOf(11), BigInteger.valueOf(4)));
            AlgorithmIdentifier elGamal = new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm,
                    new ElGamalParameter(prime, BigInteger.valueOf(5)));
            AlgorithmIdentifier explicitCurve = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    new X962Parameters(ECNamedCurveTable.getByName("secp256r1")));
            AlgorithmIdentifier implicitCurve = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    DERNull.INSTANCE);
            return Stream
                    .of(named("a Diffie-Hellman key", new SubjectPublicKeyInfo(diffieHellman, new ASN1Integer(8))),
                            named("a DSA key", new SubjectPublicKeyInfo(dsa, new ASN1Integer(8))),
                            named("an ElGamal key", new SubjectPublicKeyInfo(elGamal, new ASN1Integer(8))),
                            named("an EC key with explicit curve parameters",
                                    new SubjectPublicKeyInfo(explicitCurve, ecPoint)),
                            named("an EC key without curve parameters",
                                    new SubjectPublicKeyInfo(algorithm(X9ObjectIdentifiers.id_ecPublicKey), ecPoint)),
                            named("an EC key whose curve is implicitlyCA",
                                    new SubjectPublicKeyInfo(implicitCurve, ecPoint)),
                            named("an RSAES-OAEP key within the size caps",
                                    rsaPublicKeyInfo(PKCSObjectIdentifiers.id_RSAES_OAEP, 2048, F4)),
                            named("an X.509 id-ea-rsa key within the size caps",
                                    rsaPublicKeyInfo(X509ObjectIdentifiers.id_ea_rsa, 2048, F4)),
                            named("an X25519 key, which agrees on keys and signs nothing",
                                    new SubjectPublicKeyInfo(algorithm(EdECObjectIdentifiers.id_X25519),
                                            new byte[ED25519_PUBLIC_KEY_BYTES])),
                            named("an ML-KEM-768 key, which encapsulates keys and signs nothing",
                                    new SubjectPublicKeyInfo(algorithm(NISTObjectIdentifiers.id_alg_ml_kem_768),
                                            new byte[ML_KEM_768_PUBLIC_KEY_BYTES])),
                            named("a key of an algorithm that nobody knows", new SubjectPublicKeyInfo(
                                    algorithm(new ASN1ObjectIdentifier(UNKNOWN_ALGORITHM_OID)), UNUSABLE_BYTES)));
        }

        static Stream<Named<SubjectPublicKeyInfo>> rsaKeysWithinTheCaps() throws Exception {
            ASN1ObjectIdentifier rsaEncryption = PKCSObjectIdentifiers.rsaEncryption;
            BigInteger longestExponent = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
            return Stream
                    .of(named("an RSA key of 2048 bits", publicKeyInfoOf(rsaKeyPair(2048).getPublic())),
                            named("an RSA modulus of exactly 8192 bits", rsaPublicKeyInfo(rsaEncryption, 8192, F4)),
                            named("an RSA public exponent of 2^256 - 1",
                                    rsaPublicKeyInfo(rsaEncryption, 2048, longestExponent)),
                            named("an RSASSA-PSS key within the caps",
                                    rsaPublicKeyInfo(PKCSObjectIdentifiers.id_RSASSA_PSS, 2048, F4)));
        }

        /** Keys as BouncyCastle writes them, so the identifiers that it writes are the ones that are listed. */
        static Stream<Named<SubjectPublicKeyInfo>> keysOfASupportedAlgorithm() throws Exception {
            return Stream
                    .of(named("an EC key on a named curve", publicKeyInfoOf(ecKeyPair().getPublic())),
                            named("an Ed25519 key", publicKeyInfoOf(generatedKeyPair("Ed25519").getPublic())),
                            named("an Ed448 key", publicKeyInfoOf(generatedKeyPair("Ed448").getPublic())),
                            named("an ML-DSA key", publicKeyInfoOf(PqcKeyFixtures.keyPair().getPublic())),
                            named("an ML-DSA-44 key that signs a SHA-512 digest",
                                    publicKeyInfoOf(CertificateGeneratorHelper
                                            .generateKeyPair(KeyAlgorithm.MLDSA,
                                                    MLDSAParameterSpec.ml_dsa_44_with_sha512)
                                            .getPublic())),
                            named("an SLH-DSA key",
                                    publicKeyInfoOf(CertificateGeneratorHelper
                                            .generateKeyPair(KeyAlgorithm.SLHDSA, SLHDSAParameterSpec.slh_dsa_sha2_128f)
                                            .getPublic())),
                            named("an SLH-DSA-SHA2-128f key that signs a SHA-256 digest",
                                    publicKeyInfoOf(CertificateGeneratorHelper
                                            .generateKeyPair(KeyAlgorithm.SLHDSA,
                                                    SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256)
                                            .getPublic())),
                            named("a Falcon key",
                                    publicKeyInfoOf(CertificateGeneratorHelper
                                            .generateKeyPair(KeyAlgorithm.FALCON, FalconParameterSpec.falcon_512)
                                            .getPublic())));
        }

        /**
         * Every identifier of the algorithms whose key the identifier sizes, as the NIST and BouncyCastle registers
         * write them. A key that cannot be read is no matter here: the algorithm is judged and no key is built.
         */
        static Stream<Named<SubjectPublicKeyInfo>> keysOfEveryListedAlgorithm() {
            Map<String, String> identifiers = new LinkedHashMap<>();
            identifiers.put("Ed25519", "1.3.101.112");
            identifiers.put("Ed448", "1.3.101.113");
            identifiers.put("ML-DSA-44", "2.16.840.1.101.3.4.3.17");
            identifiers.put("ML-DSA-65", "2.16.840.1.101.3.4.3.18");
            identifiers.put("ML-DSA-87", "2.16.840.1.101.3.4.3.19");
            identifiers.put("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20");
            identifiers.put("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21");
            identifiers.put("SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22");
            identifiers.put("SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23");
            identifiers.put("SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24");
            identifiers.put("SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25");
            identifiers.put("SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26");
            identifiers.put("SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27");
            identifiers.put("SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28");
            identifiers.put("SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29");
            identifiers.put("SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30");
            identifiers.put("SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31");
            identifiers.put("HashML-DSA-44 with SHA-512", "2.16.840.1.101.3.4.3.32");
            identifiers.put("HashML-DSA-65 with SHA-512", "2.16.840.1.101.3.4.3.33");
            identifiers.put("HashML-DSA-87 with SHA-512", "2.16.840.1.101.3.4.3.34");
            identifiers.put("HashSLH-DSA-SHA2-128s with SHA-256", "2.16.840.1.101.3.4.3.35");
            identifiers.put("HashSLH-DSA-SHA2-128f with SHA-256", "2.16.840.1.101.3.4.3.36");
            identifiers.put("HashSLH-DSA-SHA2-192s with SHA-512", "2.16.840.1.101.3.4.3.37");
            identifiers.put("HashSLH-DSA-SHA2-192f with SHA-512", "2.16.840.1.101.3.4.3.38");
            identifiers.put("HashSLH-DSA-SHA2-256s with SHA-512", "2.16.840.1.101.3.4.3.39");
            identifiers.put("HashSLH-DSA-SHA2-256f with SHA-512", "2.16.840.1.101.3.4.3.40");
            identifiers.put("HashSLH-DSA-SHAKE-128s with SHAKE128", "2.16.840.1.101.3.4.3.41");
            identifiers.put("HashSLH-DSA-SHAKE-128f with SHAKE128", "2.16.840.1.101.3.4.3.42");
            identifiers.put("HashSLH-DSA-SHAKE-192s with SHAKE256", "2.16.840.1.101.3.4.3.43");
            identifiers.put("HashSLH-DSA-SHAKE-192f with SHAKE256", "2.16.840.1.101.3.4.3.44");
            identifiers.put("HashSLH-DSA-SHAKE-256s with SHAKE256", "2.16.840.1.101.3.4.3.45");
            identifiers.put("HashSLH-DSA-SHAKE-256f with SHAKE256", "2.16.840.1.101.3.4.3.46");
            identifiers.put("Falcon-512", "1.3.9999.3.11");
            identifiers.put("Falcon-1024", "1.3.9999.3.14");
            List<Named<SubjectPublicKeyInfo>> keys = new ArrayList<>();
            for (Map.Entry<String, String> identifier : identifiers.entrySet()) {
                AlgorithmIdentifier keyAlgorithm = algorithm(new ASN1ObjectIdentifier(identifier.getValue()));
                keys
                        .add(named("a key of " + identifier.getKey() + ", " + identifier.getValue(),
                                new SubjectPublicKeyInfo(keyAlgorithm, UNUSABLE_BYTES)));
            }
            return keys.stream();
        }

        /** RSA keys that no key builder builds either, so they are left to the builder, which refuses them cheaply. */
        static Stream<Named<SubjectPublicKeyInfo>> rsaKeysThatCannotBeRead() throws Exception {
            AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                    DERNull.INSTANCE);
            return Stream
                    .of(named("an RSA key that is no ASN.1 encoding",
                            new SubjectPublicKeyInfo(rsaEncryption, UNUSABLE_BYTES)),
                            named("an RSA key that is no sequence of two numbers",
                                    new SubjectPublicKeyInfo(rsaEncryption, new ASN1Integer(1))),
                            named("an RSA key whose bit string is not a whole number of bytes",
                                    new SubjectPublicKeyInfo(rsaEncryption, new DERBitString(new byte[]{1, 2, 4}, 2))));
        }
    }

    // ── RequireBoundedSignatureAlgorithm ──────────────────────────────────────

    @Nested
    class RequireBoundedSignatureAlgorithm {

        @ParameterizedTest(name = "{0}")
        @MethodSource("signatureAlgorithmsBeyondTheBounds")
        void refuses_whenAlgorithmAsksForWorkThatIsNotBounded(AlgorithmIdentifier signatureAlgorithm) {
            // given — a signature algorithm whose parameters set the work of verifying it

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds
                    .requireBoundedSignatureAlgorithm(signatureAlgorithm);

            // then
            assertThatThrownBy(require).isInstanceOf(InvalidAlgorithmParameterException.class);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("signatureAlgorithmsWithinTheBounds")
        void accepts_whenAlgorithmAsksForBoundedWork(AlgorithmIdentifier signatureAlgorithm) {
            // given — a signature algorithm whose work the key of the signer bounds

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds
                    .requireBoundedSignatureAlgorithm(signatureAlgorithm);

            // then
            assertThatCode(require).doesNotThrowAnyException();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<AlgorithmIdentifier>> signatureAlgorithmsBeyondTheBounds() {
            BigInteger twoToThe31 = BigInteger.ONE.shiftLeft(31);
            BigInteger twoToThe32 = BigInteger.ONE.shiftLeft(32);
            AlgorithmIdentifier ecdsaWithSha256 = algorithm(X9ObjectIdentifiers.ecdsa_with_SHA256);
            return Stream
                    .of(named("an RSASSA-PSS signature with a salt of 2^31 - 1 bytes",
                            pssSignatureAlgorithm(twoToThe31.subtract(BigInteger.ONE))),
                            named("an RSASSA-PSS signature with a salt of 2^32 + 20 bytes, which an int holds as 20",
                                    pssSignatureAlgorithm(twoToThe32.add(BigInteger.valueOf(20)))),
                            named("an RSASSA-PSS signature with a salt of 1025 bytes, one over the bound",
                                    pssSignatureAlgorithm(BigInteger.valueOf(1025))),
                            named("an RSASSA-PSS signature with a negative salt",
                                    pssSignatureAlgorithm(BigInteger.valueOf(-1))),
                            named("an RSASSA-PSS signature whose parameters are NULL",
                                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, DERNull.INSTANCE)),
                            named("an RSASSA-PSS signature whose parameters are a sequence of a number",
                                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                                            new DERSequence(new ASN1Integer(1)))),
                            named("a generic composite signature that lists the ECDSA algorithm 1000 times",
                                    compositeSignatureAlgorithm(ecdsaWithSha256, 1000)),
                            named("a generic composite signature that lists one algorithm",
                                    compositeSignatureAlgorithm(ecdsaWithSha256, 1)),
                            named("an EAC alias of RSASSA-PSS that states a salt of 2^31 - 1 bytes",
                                    new AlgorithmIdentifier(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256,
                                            pssSignatureAlgorithm(twoToThe31.subtract(BigInteger.ONE))
                                                    .getParameters())),
                            named("an ECDSA signature that carries parameters", new AlgorithmIdentifier(
                                    X9ObjectIdentifiers.ecdsa_with_SHA256, new ASN1Integer(1))));
        }

        static Stream<Named<AlgorithmIdentifier>> signatureAlgorithmsWithinTheBounds() {
            return Stream
                    .of(named("an RSASSA-PSS signature with a salt of 0 bytes", pssSignatureAlgorithm(BigInteger.ZERO)),
                            named("an RSASSA-PSS signature with the longest salt that a 2048-bit key allows, 222 bytes",
                                    pssSignatureAlgorithm(BigInteger.valueOf(222))),
                            named("an RSASSA-PSS signature with a salt of 1024 bytes, the bound",
                                    pssSignatureAlgorithm(BigInteger.valueOf(1024))),
                            named("an RSASSA-PSS signature without parameters",
                                    algorithm(PKCSObjectIdentifiers.id_RSASSA_PSS)),
                            named("an EAC alias of RSASSA-PSS without parameters",
                                    algorithm(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256)),
                            named("an RSA signature over SHA-256",
                                    new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption,
                                            DERNull.INSTANCE)),
                            named("an ECDSA signature over SHA-256", algorithm(X9ObjectIdentifiers.ecdsa_with_SHA256)),
                            named("an Ed25519 signature", algorithm(EdECObjectIdentifiers.id_Ed25519)),
                            named("an ML-DSA-65 signature", algorithm(NISTObjectIdentifiers.id_ml_dsa_65)),
                            named("an ML-DSA-44 signature of a SHA-512 digest",
                                    algorithm(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512)),
                            named("a signature algorithm that nobody knows, which no verifier is built for",
                                    algorithm(new ASN1ObjectIdentifier(UNKNOWN_ALGORITHM_OID))));
        }
    }

    // ── RequireBoundedRequest ─────────────────────────────────────────────────

    @Nested
    class RequireBoundedRequest {

        @ParameterizedTest(name = "{0}")
        @MethodSource("requestsWithAKeyBeyondTheBounds")
        void refusesTheKey_whenAKeyOfTheRequestIsBeyondTheBounds(PKCS10CertificationRequest request) {
            // given — a request whose public key or alternative public key is beyond the bounds

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds.requireBoundedRequest(request);

            // then
            assertThatThrownBy(require).isInstanceOf(InvalidKeyException.class);
        }

        @Test
        void refusesTheSignatureAlgorithm_whenItIsBeyondTheBounds() throws Exception {
            // given
            AlgorithmIdentifier saltOneOverTheBound = pssSignatureAlgorithm(BigInteger.valueOf(1025));
            PKCS10CertificationRequest request = withSignatureAlgorithm(signedRequest(rsaKeyPair(2048)),
                    saltOneOverTheBound);

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds.requireBoundedRequest(request);

            // then
            assertThatThrownBy(require).isInstanceOf(InvalidAlgorithmParameterException.class);
        }

        @Test
        void accepts_whenBothKeysAreSupportedAndTheSignatureAlgorithmIsBounded() throws Exception {
            // given
            KeyPair keyPair = ecKeyPair();
            SubjectPublicKeyInfo alternativeKey = publicKeyInfoOf(PqcKeyFixtures.keyPair().getPublic());
            PKCS10CertificationRequest request = requestCarrying(publicKeyInfoOf(keyPair.getPublic()), alternativeKey);

            // when
            ThrowingCallable require = () -> SignatureVerificationBounds.requireBoundedRequest(request);

            // then
            assertThatCode(require).doesNotThrowAnyException();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<PKCS10CertificationRequest>> requestsWithAKeyBeyondTheBounds() throws Exception {
            SubjectPublicKeyInfo supportedKey = publicKeyInfoOf(ecKeyPair().getPublic());
            SubjectPublicKeyInfo rsaKeyOf16384Bits = rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);
            SubjectPublicKeyInfo compositeOfThatKey = new SubjectPublicKeyInfo(
                    algorithm(MiscObjectIdentifiers.id_alg_composite), new DERSequence(rsaKeyOf16384Bits));
            return Stream
                    .of(named("a public key beyond the bounds", requestCarrying(rsaKeyOf16384Bits, null)),
                            named("an alternative public key beyond the bounds",
                                    requestCarrying(supportedKey, rsaKeyOf16384Bits)),
                            named("an alternative public key of the generic composite algorithm",
                                    requestCarrying(supportedKey, compositeOfThatKey)));
        }

        /**
         * A request that carries the public key and, unless it is null, the alternative public key with the alternative
         * signature attributes that go with it, signed with unrelated keys, since no signature is verified here.
         */
        private static PKCS10CertificationRequest requestCarrying(SubjectPublicKeyInfo publicKey,
                SubjectPublicKeyInfo alternativePublicKey) throws Exception {
            PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(new X500Name(SUBJECT),
                    publicKey);
            return alternativePublicKey == null
                    ? builder.build(unrelatedSigner())
                    : builder.build(unrelatedSigner(), alternativePublicKey, unrelatedSigner());
        }

        private static PKCS10CertificationRequest signedRequest(KeyPair keyPair) throws Exception {
            return new JcaPKCS10CertificationRequestBuilder(new X500Name(SUBJECT), keyPair.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(keyPair.getPrivate()));
        }

        /** The request with another signature algorithm, which keeps the signature value that it had. */
        private static PKCS10CertificationRequest withSignatureAlgorithm(PKCS10CertificationRequest signed,
                AlgorithmIdentifier signatureAlgorithm) {
            CertificationRequest structure = signed.toASN1Structure();
            return new PKCS10CertificationRequest(new CertificationRequest(structure.getCertificationRequestInfo(),
                    signatureAlgorithm, structure.getSignature()));
        }

        private static ContentSigner unrelatedSigner() throws Exception {
            return new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(ecKeyPair().getPrivate());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static AlgorithmIdentifier algorithm(ASN1ObjectIdentifier identifier) {
        return new AlgorithmIdentifier(identifier);
    }

    private static SubjectPublicKeyInfo publicKeyInfoOf(PublicKey publicKey) {
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    }

    private static KeyPair ecKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp256r1"));
    }

    private static KeyPair rsaKeyPair(int bits) throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, new RSAKeyGenParameterSpec(bits, F4));
    }

    private static KeyPair generatedKeyPair(String algorithm) throws Exception {
        return KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();
    }

    private static byte[] concatenated(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }
}
