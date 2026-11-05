package com.otilm.core.service.scep.message;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.util.CertificateTestUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.Mockito.mockConstruction;

/**
 * The envelope of a request is opened before the client is authenticated, so the key derivations that the client states
 * for it, that of a password recipient and any that its content-encryption algorithm brings, are judged before any key
 * is derived.
 */
@ExtendWith(MockitoExtension.class)
class ScepRequestKeyDerivationTest {

    private static final BigInteger ONE_OVER_THE_BOUND = BigInteger
            .valueOf(ScepRequest.MAX_PBKDF2_ITERATION_COUNT + 1L);
    private static final BigInteger TWO_TO_THE_32_PLUS_1 = BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE);
    private static final BigInteger WITHIN_THE_BOUND = BigInteger.valueOf(1_024);

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── PasswordRecipient ─────────────────────────────────────────────────────

    @Nested
    class PasswordRecipient {

        @ParameterizedTest(name = "{0}")
        @MethodSource("unsupportedKeyDerivations")
        void refusesWithBadAlgBeforeDerivingAKey_whenKeyDerivationIsNotSupported(AlgorithmIdentifier keyDerivation)
                throws Exception {
            // given
            ScepRequest request = new ScepRequest(ScepMessageTestData.pkcsReqStatingKeyDerivation(keyDerivation));

            try (MockedConstruction<JcePasswordEnvelopedRecipient> recipients = mockConstruction(
                    JcePasswordEnvelopedRecipient.class)) {
                // when
                ThrowingCallable decrypt = () -> request
                        .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

                // then
                assertThatThrownBy(decrypt)
                        .hasMessageContaining("password recipient")
                        .isInstanceOfSatisfying(ScepException.class,
                                thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
                assertThat(recipients.constructed()).isEmpty();
            }
        }

        @Test
        void refusesWithBadAlg_whenRecipientIsNotAPasswordRecipient() throws Exception {
            // given — a request enveloped by key transport, which a CA key that is not RSA cannot open
            KeyPair rsaCaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            X509Certificate rsaCaCertificate = CertificateTestUtil.generateRandomX509Certificate(rsaCaKeyPair);
            ScepRequest request = new ScepRequest(ScepMessageTestData
                    .keyTransportEnvelopedPkcsReq(rsaCaCertificate, ScepMessageTestData.SUBJECT_DN, List.of(), null));

            // when
            ThrowingCallable decrypt = () -> request
                    .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThatThrownBy(decrypt)
                    .hasMessageContaining("password recipient")
                    .isInstanceOfSatisfying(ScepException.class,
                            thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
        }

        @Test
        void decrypts_whenIterationCountIsAtTheBound() throws Exception {
            // given
            int iterationsAtTheBound = ScepRequest.MAX_PBKDF2_ITERATION_COUNT;
            ScepRequest request = new ScepRequest(
                    ScepMessageTestData.pkcsReqEnvelopedWithIterations(iterationsAtTheBound));

            // when
            request.decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThat(request.getPkcs10Request()).isNotNull();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static Stream<Named<AlgorithmIdentifier>> unsupportedKeyDerivations() {
            return Stream
                    .of(named("PBKDF2 with one iteration over the bound", pbkdf2With(ONE_OVER_THE_BOUND)),
                            named("PBKDF2 with 2^32 + 1 iterations, which read as 1 when narrowed to an int",
                                    pbkdf2With(TWO_TO_THE_32_PLUS_1)),
                            named("PBKDF2 with no iterations", pbkdf2With(BigInteger.ZERO)),
                            named("PBKDF2 parameters that cannot be read",
                                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, DERNull.INSTANCE)),
                            named("scrypt stating PBKDF2 parameters within the bound, which BouncyCastle runs as PBKDF2",
                                    new AlgorithmIdentifier(MiscObjectIdentifiers.id_scrypt,
                                            pbkdf2With(WITHIN_THE_BOUND).getParameters())),
                            named("no key derivation algorithm", null));
        }

        /** PBKDF2 over the iteration count with a salt of 16 bytes and the default pseudorandom function, HMAC-SHA1. */
        private static AlgorithmIdentifier pbkdf2With(BigInteger iterationCount) {
            DERSequence parameters = new DERSequence(
                    new ASN1Encodable[]{new DEROctetString(new byte[16]), new ASN1Integer(iterationCount)});
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, parameters);
        }
    }

    // ── ContentEncryption ─────────────────────────────────────────────────────

    @Nested
    class ContentEncryption {

        @Mock
        private PlatformPrivateKey caKey;

        @ParameterizedTest(name = "{0}")
        @MethodSource("requestsWithPasswordBasedContentEncryption")
        void refusesWithBadAlgBeforeOpeningTheEnvelope_whenContentEncryptionIsPasswordBased(
                EnvelopedRequest envelopedRequest) throws Exception {
            // given
            ScepRequest request = new ScepRequest(envelopedRequest.message());
            Provider caKeyProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

            try (MockedConstruction<JceKeyTransEnvelopedRecipient> keyTransportRecipients = mockConstruction(
                    JceKeyTransEnvelopedRecipient.class);
                    MockedConstruction<JcePasswordEnvelopedRecipient> passwordRecipients = mockConstruction(
                            JcePasswordEnvelopedRecipient.class)) {
                // when
                ThrowingCallable decrypt = () -> request
                        .decryptData(caKey, caKeyProvider, envelopedRequest.caKeyAlgorithm(),
                                ScepMessageTestData.CHALLENGE_PASSWORD);

                // then
                assertThatThrownBy(decrypt)
                        .hasMessageContaining("encrypted with")
                        .isInstanceOfSatisfying(ScepException.class,
                                thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
                assertThat(keyTransportRecipients.constructed()).isEmpty();
                assertThat(passwordRecipients.constructed()).isEmpty();
            }
        }

        @Test
        void refusesWithBadAlg_whenContentIsEncryptedWithSingleDes() throws Exception {
            // given — single DES, which RFC 8894 forbids
            ASN1ObjectIdentifier singleDes = CMSAlgorithm.DES_CBC;
            ScepRequest request = new ScepRequest(ScepMessageTestData.passwordEnvelopedPkcsReqEncryptedWith(singleDes));

            // when
            ThrowingCallable decrypt = () -> request
                    .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThatThrownBy(decrypt)
                    .hasMessageContaining("encrypted with")
                    .isInstanceOfSatisfying(ScepException.class,
                            thrown -> assertThat(thrown.getFailInfo()).isEqualTo(FailInfo.BAD_ALG));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("supportedContentEncryptionAlgorithms")
        void decrypts_whenContentIsEncryptedWithASupportedAlgorithm(ASN1ObjectIdentifier contentEncryptionAlgorithm)
                throws Exception {
            // given
            ScepRequest request = new ScepRequest(
                    ScepMessageTestData.passwordEnvelopedPkcsReqEncryptedWith(contentEncryptionAlgorithm));

            // when
            request.decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);

            // then
            assertThat(request.getPkcs10Request()).isNotNull();
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static Stream<Named<EnvelopedRequest>> requestsWithPasswordBasedContentEncryption() throws Exception {
            AlgorithmIdentifier pkcs12TripleDes = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                    new PKCS12PBEParams(new byte[8], WITHIN_THE_BOUND.intValue()));
            KeyPair rsaCaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            X509Certificate rsaCaCertificate = CertificateTestUtil.generateRandomX509Certificate(rsaCaKeyPair);
            return Stream
                    .of(named("to an RSA CA key, which needs only the CA certificate to reach the content cipher",
                            new EnvelopedRequest(ScepMessageTestData
                                    .keyTransportEnvelopedPkcsReqStatingContentEncryption(rsaCaCertificate,
                                            pkcs12TripleDes),
                                    KeyAlgorithm.RSA)),
                            named("to a CA key that is not RSA, through its password recipient",
                                    new EnvelopedRequest(
                                            ScepMessageTestData
                                                    .passwordEnvelopedPkcsReqStatingContentEncryption(pkcs12TripleDes),
                                            KeyAlgorithm.ECDSA)));
        }

        private static Stream<Named<ASN1ObjectIdentifier>> supportedContentEncryptionAlgorithms() {
            return Stream
                    .of(named("AES-128-CBC", CMSAlgorithm.AES128_CBC), named("AES-192-CBC", CMSAlgorithm.AES192_CBC),
                            named("AES-256-CBC", CMSAlgorithm.AES256_CBC),
                            named("DES-EDE3-CBC", CMSAlgorithm.DES_EDE3_CBC));
        }

        /** A request and the algorithm of the CA key that it is enveloped to. */
        private record EnvelopedRequest(byte[] message, KeyAlgorithm caKeyAlgorithm) {
        }
    }
}
