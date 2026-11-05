package com.otilm.core.service.scep.message;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.util.PqcKeyFixtures;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;

import static com.otilm.core.util.SignatureVerificationBoundsFixtures.compositeSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.pssSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.rsaPublicKeyInfo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

/**
 * The signatures that a SCEP request carries are verified before the client may be authenticated, so what a client
 * states about their keys and algorithms is judged before BouncyCastle builds anything from it.
 */
class ScepRequestVerificationTest {

    private static final String SUBJECT = "CN=scep-client";
    private static final String RSA_SIGNATURE = "SHA256withRSA";
    private static final String ECDSA_SIGNATURE = "SHA256withECDSA";
    private static final BigInteger F4 = RSAKeyGenParameterSpec.F4;
    private static final BigInteger SALT_OF_2_TO_THE_31_MINUS_1 = BigInteger.ONE.shiftLeft(31).subtract(BigInteger.ONE);
    private static final BigInteger SALT_ONE_OVER_THE_BOUND = BigInteger.valueOf(1025);

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── SignerCertificate ─────────────────────────────────────────────────────

    @Nested
    class SignerCertificate {

        @Test
        void refusesWithoutConvertingIt_whenItsKeyIsBeyondTheBounds() throws Exception {
            // given
            KeyPair signingKeyPair = ecKeyPair();
            X509CertificateHolder compositeCertificate = certificateCarrying(compositeOfAnRsaKeyOf16384Bits(),
                    signingKeyPair);
            byte[] message = ScepMessageTestData
                    .passwordEnvelopedPkcsReqSignedWith(signingKeyPair.getPrivate(), compositeCertificate,
                            List.of(compositeCertificate));
            var realConverter = new JcaX509CertificateConverter();

            try (MockedConstruction<JcaX509CertificateConverter> converters = convertingWith(realConverter)) {
                // when
                ThrowingCallable parse = () -> new ScepRequest(message);

                // then
                assertThatThrownBy(parse).isInstanceOf(ScepException.class);
                assertThat(converters.constructed()).isEmpty();
            }
        }

        @Test
        void readsTheCertificateWithASupportedKey_whenAnotherMatchingCertificateIsBeyondTheBounds() throws Exception {
            // given — two certificates of the same issuer and serial number, so both match the signer
            KeyPair signingKeyPair = ecKeyPair();
            SubjectPublicKeyInfo signingKey = SubjectPublicKeyInfo.getInstance(signingKeyPair.getPublic().getEncoded());
            X509CertificateHolder signerCertificate = certificateCarrying(signingKey, signingKeyPair);
            X509CertificateHolder compositeTwin = certificateCarrying(compositeOfAnRsaKeyOf16384Bits(), signingKeyPair);
            byte[] message = ScepMessageTestData
                    .passwordEnvelopedPkcsReqSignedWith(signingKeyPair.getPrivate(), signerCertificate,
                            List.of(compositeTwin, signerCertificate));
            var realConverter = new JcaX509CertificateConverter();

            try (MockedConstruction<JcaX509CertificateConverter> converters = convertingWith(realConverter)) {
                // when
                ScepRequest request = new ScepRequest(message);

                // then
                assertThat(request.getSignerCertificate().getEncoded()).isEqualTo(signerCertificate.getEncoded());
                assertThat(converters.constructed()).hasSize(1);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        /** Lets each conversion of a certificate, which builds its key, run on the real converter and be counted. */
        private static MockedConstruction<JcaX509CertificateConverter> convertingWith(
                JcaX509CertificateConverter realConverter) {
            return mockConstruction(JcaX509CertificateConverter.class,
                    (converter, context) -> when(converter.getCertificate(any()))
                            .thenAnswer(invocation -> realConverter.getCertificate(invocation.getArgument(0))));
        }

        /** A certificate for the public key as it is encoded, so that no key is built for it. */
        private static X509CertificateHolder certificateCarrying(SubjectPublicKeyInfo publicKey, KeyPair issuerKeyPair)
                throws Exception {
            X500Name name = new X500Name(SUBJECT);
            Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
            Date notAfter = new Date(System.currentTimeMillis() + 3_600_000L);
            return new X509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, publicKey)
                    .build(signerOf(issuerKeyPair, ECDSA_SIGNATURE));
        }
    }

    // ── DecryptData ───────────────────────────────────────────────────────────

    @Nested
    class DecryptData {

        @ParameterizedTest(name = "{0}")
        @MethodSource("csrsBeyondTheBounds")
        void refusesWithBadAlgAndKeepsNoCsr_whenCsrIsBeyondTheBounds(byte[] csr) throws Exception {
            // given
            ScepRequest request = requestCarrying(MessageType.PKCS_REQ, csr);

            // when
            ThrowingCallable decrypt = () -> request
                    .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThatThrownBy(decrypt)
                    .isInstanceOfSatisfying(ScepException.class,
                            thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
            assertThat(request.getPkcs10Request()).isNull();
        }

        @Test
        void refusesWithBadAlg_whenCsrOfARenewalRequestIsBeyondTheBounds() throws Exception {
            // given — a renewal request, whose proof of possession is not verified
            ScepRequest request = requestCarrying(MessageType.RENEWAL_REQ, csrCarrying(rsaKeyOf16384Bits(), null));

            // when
            ThrowingCallable decrypt = () -> request
                    .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThatThrownBy(decrypt)
                    .isInstanceOfSatisfying(ScepException.class,
                            thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<byte[]>> csrsBeyondTheBounds() throws Exception {
            CertificationRequest signedWithRsa = signedCsr(rsaKeyPair(), RSA_SIGNATURE);
            CertificationRequest signedWithEc = signedCsr(ecKeyPair(), ECDSA_SIGNATURE);
            AlgorithmIdentifier ecdsaWithSha256 = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            SubjectPublicKeyInfo supportedKey = SubjectPublicKeyInfo.getInstance(ecKeyPair().getPublic().getEncoded());
            return Stream
                    .of(named("an RSA key whose modulus has 16384 bits", csrCarrying(rsaKeyOf16384Bits(), null)),
                            named("a generic composite key that holds that RSA key",
                                    csrCarrying(compositeOfAnRsaKeyOf16384Bits(), null)),
                            named("an alternative public key of the generic composite algorithm",
                                    csrCarrying(supportedKey, compositeOfAnRsaKeyOf16384Bits())),
                            named("an RSASSA-PSS signature with a salt of 2^31 - 1 bytes",
                                    withSignatureAlgorithm(signedWithRsa,
                                            pssSignatureAlgorithm(SALT_OF_2_TO_THE_31_MINUS_1))),
                            named("an RSASSA-PSS signature with a salt of 1025 bytes, one over the bound",
                                    withSignatureAlgorithm(signedWithRsa,
                                            pssSignatureAlgorithm(SALT_ONE_OVER_THE_BOUND))),
                            named("a generic composite signature that lists the ECDSA algorithm 1000 times",
                                    withSignatureAlgorithm(signedWithEc,
                                            compositeSignatureAlgorithm(ecdsaWithSha256, 1000))));
        }

        /** The request with another signature algorithm, which keeps the signature value that it had. */
        private static byte[] withSignatureAlgorithm(CertificationRequest signed,
                AlgorithmIdentifier signatureAlgorithm) throws IOException {
            return derOf(new CertificationRequest(signed.getCertificationRequestInfo(), signatureAlgorithm,
                    signed.getSignature()));
        }

        /**
         * A CSR that carries the public key and, unless it is null, the alternative public key with the alternative
         * signature attributes that go with it, signed with unrelated keys, so that its signatures do not verify.
         */
        private static byte[] csrCarrying(SubjectPublicKeyInfo publicKey, SubjectPublicKeyInfo alternativePublicKey)
                throws Exception {
            PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(new X500Name(SUBJECT),
                    publicKey);
            ContentSigner unrelatedSigner = signerOf(ecKeyPair(), ECDSA_SIGNATURE);
            PKCS10CertificationRequest csr = alternativePublicKey == null
                    ? builder.build(unrelatedSigner)
                    : builder.build(unrelatedSigner, alternativePublicKey, unrelatedSigner);
            return csr.getEncoded();
        }
    }

    // ── VerifyRequest ─────────────────────────────────────────────────────────

    @Nested
    class VerifyRequest {

        @ParameterizedTest(name = "{0}")
        @MethodSource("csrsSignedWithTheKeyTheyCarry")
        void verifies_whenCsrIsSignedWithTheSupportedKeyItCarries(byte[] csr) throws Exception {
            // given
            ScepRequest request = requestCarrying(MessageType.PKCS_REQ, csr);
            request.decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // when
            boolean verified = request.verifyRequest();

            // then
            assertThat(verified).isTrue();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<byte[]>> csrsSignedWithTheKeyTheyCarry() throws Exception {
            KeyPair preHashMlDsa = CertificateGeneratorHelper
                    .generateKeyPair(KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_44_with_sha512);
            KeyPair slhDsa = CertificateGeneratorHelper
                    .generateKeyPair(KeyAlgorithm.SLHDSA, SLHDSAParameterSpec.slh_dsa_sha2_128f);
            KeyPair preHashSlhDsa = CertificateGeneratorHelper
                    .generateKeyPair(KeyAlgorithm.SLHDSA, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256);
            return Stream
                    .of(named("an RSA key of 2048 bits", derOf(signedCsr(rsaKeyPair(), RSA_SIGNATURE))),
                            named("an EC key on a named curve", derOf(signedCsr(ecKeyPair(), ECDSA_SIGNATURE))),
                            named("an EC key with an alternative ML-DSA key", hybridCsr()),
                            named("an Ed25519 key", derOf(signedCsr(generatedKeyPair("Ed25519"), "Ed25519"))),
                            named("an ML-DSA key", derOf(signedCsr(PqcKeyFixtures.keyPair(), "ML-DSA"))),
                            named("an ML-DSA-44 key that signs a SHA-512 digest",
                                    derOf(signedCsr(preHashMlDsa, "HASH-ML-DSA"))),
                            named("an SLH-DSA key", derOf(signedCsr(slhDsa, "SLH-DSA"))),
                            named("an SLH-DSA-SHA2-128f key that signs a SHA-256 digest",
                                    derOf(signedCsr(preHashSlhDsa, "HASH-SLH-DSA"))),
                            named("an RSASSA-PSS signature with a salt of 32 bytes", pssSignedCsr(32)),
                            named("an RSASSA-PSS signature with the longest salt that a 2048-bit key allows, 222 bytes",
                                    pssSignedCsr(222)));
        }

        /** A request for an EC key and, as its alternative public key, an ML-DSA key, signed with both. */
        private static byte[] hybridCsr() throws Exception {
            KeyPair keyPair = ecKeyPair();
            KeyPair alternativeKeyPair = PqcKeyFixtures.keyPair();
            SubjectPublicKeyInfo alternativeKey = SubjectPublicKeyInfo
                    .getInstance(alternativeKeyPair.getPublic().getEncoded());
            return new JcaPKCS10CertificationRequestBuilder(new X500Name(SUBJECT), keyPair.getPublic())
                    .build(signerOf(keyPair, ECDSA_SIGNATURE), alternativeKey, signerOf(alternativeKeyPair, "ML-DSA"))
                    .getEncoded();
        }

        /** A request for an RSA key of 2048 bits, signed with RSASSA-PSS over SHA-256 and the salt length as given. */
        private static byte[] pssSignedCsr(int saltLength) throws Exception {
            KeyPair keyPair = rsaKeyPair();
            PSSParameterSpec parameters = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLength,
                    PSSParameterSpec.TRAILER_FIELD_BC);
            ContentSigner signer = new JcaContentSignerBuilder("RSASSA-PSS", parameters)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());
            return new JcaPKCS10CertificationRequestBuilder(new X500Name(SUBJECT), keyPair.getPublic())
                    .build(signer)
                    .getEncoded();
        }

        private static KeyPair generatedKeyPair(String algorithm) throws Exception {
            return KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();
        }
    }

    // ── VerifySignature ───────────────────────────────────────────────────────

    @Nested
    class VerifySignature {

        @ParameterizedTest(name = "{0}")
        @MethodSource("signatureAlgorithmsBeyondTheBounds")
        void refuses_whenSignerStatesAnAlgorithmBeyondTheBounds(AlgorithmIdentifier signatureAlgorithm)
                throws Exception {
            // given — the key of a certificate that the platform knows, of the type that the stated algorithm takes
            byte[] message = withSignerAlgorithm(ScepMessageTestData.passwordEnvelopedPkcsReq(), signatureAlgorithm);
            ScepRequest request = new ScepRequest(message);
            PublicKey rsaKey = rsaKeyPair().getPublic();

            // when
            ThrowingCallable verify = () -> request.verifySignature(rsaKey);

            // then
            assertThatThrownBy(verify).isInstanceOf(InvalidAlgorithmParameterException.class);
        }

        @Test
        void verifies_whenMessageIsSignedWithTheSignerCertificateKey() throws Exception {
            // given
            ScepRequest request = new ScepRequest(ScepMessageTestData.passwordEnvelopedPkcsReq());
            PublicKey signerKey = ScepMessageTestData.signerCertificate().getPublicKey();

            // when
            boolean verified = request.verifySignature(signerKey);

            // then
            assertThat(verified).isTrue();
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("signatureAlgorithmsBeyondTheBounds")
        void ignoresCounterSignatures_whenTheMessageSignatureVerifies(AlgorithmIdentifier counterSignatureAlgorithm)
                throws Exception {
            // given — an unsigned counterSignature attribute, which leaves the signature of the message valid
            byte[] message = withCounterSignature(ScepMessageTestData.passwordEnvelopedPkcsReq(),
                    counterSignatureAlgorithm);
            ScepRequest request = new ScepRequest(message);
            PublicKey signerKey = ScepMessageTestData.signerCertificate().getPublicKey();

            // when
            boolean verified = request.verifySignature(signerKey);

            // then
            assertThat(verified).isTrue();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        static Stream<Named<AlgorithmIdentifier>> signatureAlgorithmsBeyondTheBounds() {
            AlgorithmIdentifier ecdsaWithSha256 = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            return Stream
                    .of(named("an RSASSA-PSS signature with a salt of 2^31 - 1 bytes",
                            pssSignatureAlgorithm(SALT_OF_2_TO_THE_31_MINUS_1)),
                            named("an RSASSA-PSS signature with a salt of 1025 bytes, one over the bound",
                                    pssSignatureAlgorithm(SALT_ONE_OVER_THE_BOUND)),
                            named("a generic composite signature that lists the ECDSA algorithm 1000 times",
                                    compositeSignatureAlgorithm(ecdsaWithSha256, 1000)),
                            named("an EAC alias of RSASSA-PSS that states a salt of 2^31 - 1 bytes",
                                    new AlgorithmIdentifier(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256,
                                            pssSignatureAlgorithm(SALT_OF_2_TO_THE_31_MINUS_1).getParameters())));
        }

        /** The message with its signer stating another signature algorithm, the signature value kept as it was. */
        private static byte[] withSignerAlgorithm(byte[] message, AlgorithmIdentifier signatureAlgorithm)
                throws IOException {
            SignerInfo signer = signerOf(message);
            SignerInfo restatedSigner = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                    signer.getAuthenticatedAttributes(), signatureAlgorithm, signer.getEncryptedDigest(),
                    signer.getUnauthenticatedAttributes());
            return withSigner(message, restatedSigner);
        }

        /**
         * The message with a counterSignature attribute that states the algorithm. The attribute is unsigned, so the
         * signature of the message does not cover it.
         */
        private static byte[] withCounterSignature(byte[] message, AlgorithmIdentifier counterSignatureAlgorithm)
                throws IOException {
            SignerInfo signer = signerOf(message);
            SignerInfo counterSigner = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(), (ASN1Set) null,
                    counterSignatureAlgorithm, new DEROctetString(new byte[64]), (ASN1Set) null);
            Attribute counterSignature = new Attribute(CMSAttributes.counterSignature, new DERSet(counterSigner));
            SignerInfo countersignedSigner = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                    signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                    signer.getEncryptedDigest(), new DERSet(counterSignature));
            return withSigner(message, countersignedSigner);
        }

        private static SignerInfo signerOf(byte[] message) {
            SignedData signedData = SignedData.getInstance(ContentInfo.getInstance(message).getContent());
            return SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
        }

        /** The message with the signer in place of the one that it has. */
        private static byte[] withSigner(byte[] message, SignerInfo signer) throws IOException {
            SignedData signedData = SignedData.getInstance(ContentInfo.getInstance(message).getContent());
            SignedData restated = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                    signedData.getCertificates(), signedData.getCRLs(), new DERSet(signer));
            return new ContentInfo(CMSObjectIdentifiers.signedData, restated).getEncoded(ASN1Encoding.DER);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A request of the type that carries the CSR, which it envelopes to the challenge password. */
    private static ScepRequest requestCarrying(MessageType messageType, byte[] csr) throws Exception {
        return new ScepRequest(ScepMessageTestData.passwordEnvelopedMessageWithCsr(messageType, csr));
    }

    private static CertificationRequest signedCsr(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(SUBJECT), keyPair.getPublic())
                .build(signerOf(keyPair, signatureAlgorithm))
                .toASN1Structure();
    }

    private static byte[] derOf(CertificationRequest request) throws IOException {
        return request.getEncoded(ASN1Encoding.DER);
    }

    private static ContentSigner signerOf(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        return new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
    }

    private static SubjectPublicKeyInfo rsaKeyOf16384Bits() throws IOException {
        return rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);
    }

    /** A generic composite key that holds an RSA key of 16384 bits, as a key of the algorithm is encoded. */
    private static SubjectPublicKeyInfo compositeOfAnRsaKeyOf16384Bits() throws IOException {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite),
                new DERSequence(rsaKeyOf16384Bits()));
    }

    private static KeyPair ecKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp256r1"));
    }

    private static KeyPair rsaKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, new RSAKeyGenParameterSpec(2048, F4));
    }
}
