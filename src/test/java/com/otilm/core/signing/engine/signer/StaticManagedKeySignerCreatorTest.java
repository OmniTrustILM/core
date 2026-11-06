package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class StaticManagedKeySignerCreatorTest {

    @Mock
    private CryptographicOperationInternalService cryptographicOperationService;

    private StaticManagedKeySignerCreator creator;

    @BeforeEach
    void createSignerCreator() {
        creator = new StaticManagedKeySignerCreator(cryptographicOperationService);
    }

    // ── Supports ──────────────────────────────────────────────────────────────

    @Nested
    class Supports {

        @Test
        void returnsTrue_forResolvedStaticKeyManagedSigning() {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(), List.of(), null, List.of());

            // when / then
            assertThat(creator.supports(scheme)).isTrue();
        }
    }

    // ── Create ────────────────────────────────────────────────────────────────

    @Nested
    class Create {

        @Test
        void throwsMisconfigured_whenCertificateHasNoKey() {
            // given — the certificate is not backed by a managed cryptographic key (no key UUID)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.aSigningCertificate().withoutKey().build(), List.of(), null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }

        @Test
        void throwsMisconfigured_whenKeyHasNoPrivateKeyItem() {
            // given — the key only holds a public key item (no private key to sign with)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List.of(CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)), null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }

        @Test
        void throwsMisconfigured_carryingTheReason_whenThePlatformHasNoEntryForTheAlgorithm() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new ValidationException(ValidationError
                            .create("Signature algorithm SHA1WITHRSA is not one the platform supports.")));

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.MISCONFIGURED);
                        assertThat(((SigningEngineException) ex).operatorMessage()).contains("SHA1WITHRSA");
                        assertThat(((SigningEngineException) ex).clientMessage())
                                .isEqualTo("Signing configuration is not supported.");
                    });
        }

        @Test
        void throwsMisconfigured_carryingTheReason_whenTheSigningAttributesAreRejected() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new ValidationException(
                            ValidationError.create("Attribute signatureScheme is not defined in the schema.")));

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.MISCONFIGURED);
                        assertThat(((SigningEngineException) ex).operatorMessage()).contains("signatureScheme");
                        assertThat(((SigningEngineException) ex).clientMessage())
                                .isEqualTo("Signing configuration is not supported.");
                    });
        }

        @Test
        void letsAnUnexpectedDefectEscape_ratherThanCallingItMisconfigured() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new IllegalStateException("connection pool exhausted"));

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("connection pool exhausted");
        }

        @Test
        void throwsMisconfigured_whenTheKeysConnectorIsNotFound() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new NotFoundException(Connector.class, UUID.randomUUID()));

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.MISCONFIGURED);
                        assertThat(((SigningEngineException) ex).clientMessage())
                                .isEqualTo("Internal error: signing configuration is invalid");
                    });
        }

        @Test
        void throwsMisconfigured_whenKeyHasNoPublicKeyItem() {
            // given — only a private (RSA) key item is present; the signer still requires a public key item
            // even for classical algorithms, so this must fail (regression guard for the record-based path)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List.of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA)), null,
                    List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }

        @Test
        void carriesTheResolvedAlgorithm() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA),
                                    CryptographicKeyItemModelFixtures
                                            .publicKey(KeyAlgorithm.MLDSA, SignatureAlgorithm.ML_DSA_65.getCode())),
                    buildChain(generateKeyPair()), List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willReturn(SignatureAlgorithm.ML_DSA_65);

            // when
            Signer signer = creator.create(scheme);

            // then
            assertThat(signer.getSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.ML_DSA_65);
        }

        @Test
        void resolvesFromBothKeyItemsAndTheAttributes() throws Exception {
            // given
            var privateKey = CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA);
            var publicKey = CryptographicKeyItemModelFixtures
                    .publicKey(KeyAlgorithm.MLDSA, SignatureAlgorithm.ML_DSA_65.getCode());
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(), List.of(privateKey, publicKey), buildChain(generateKeyPair()),
                    List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willReturn(SignatureAlgorithm.ML_DSA_65);

            // when
            creator.create(scheme);

            // then
            then(cryptographicOperationService).should().resolveSignatureAlgorithm(privateKey, publicKey, List.of());
        }

        @Test
        void acceptsASignatureByTheCertificatesKey() throws Exception {
            // given
            var keyPair = generateKeyPair();
            var signer = createRsaSigner(keyPair);
            var message = new byte[]{1, 2, 3};
            var jdkSignature = signWithJdk(keyPair, message);
            given(cryptographicOperationService
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any(),
                            eq(SignatureInputMode.PREHASHED_DIGEST)))
                    .willReturn(answerWithSignature(jdkSignature));

            // when
            List<byte[]> signatures = signer
                    .signAll(List.of(hashWithSha256(message)), SignatureInputMode.PREHASHED_DIGEST);

            // then
            assertThat(signatures).containsExactly(jdkSignature);
        }

        @Test
        void throwsSignerFault_whenAnotherKeySigned() throws Exception {
            // given
            var signer = createRsaSigner(generateKeyPair());
            var message = new byte[]{1, 2, 3};
            var signatureByAnotherKey = signWithJdk(generateKeyPair(), message);
            given(cryptographicOperationService
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any(),
                            eq(SignatureInputMode.PREHASHED_DIGEST)))
                    .willReturn(answerWithSignature(signatureByAnotherKey));

            // when
            ThrowingCallable signDigest = () -> signer
                    .signAll(List.of(hashWithSha256(message)), SignatureInputMode.PREHASHED_DIGEST);

            // then
            assertThatThrownBy(signDigest).isInstanceOfSatisfying(SigningEngineException.class, ex -> {
                assertThat(ex.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT);
                assertThat(ex.operatorMessage()).contains("does not verify");
            });
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private Signer createRsaSigner(KeyPair signingKeyPair) throws Exception {
            var scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    buildChain(signingKeyPair), List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willReturn(SignatureAlgorithm.SHA256_WITH_RSA);
            return creator.create(scheme);
        }

        private static KeyPair generateKeyPair() throws Exception {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }

        private static CertificateChain buildChain(KeyPair signingKeyPair) throws Exception {
            var caKeys = generateKeyPair();
            var caCertificate = CertificateGeneratorHelper.generateCACertificate(caKeys, "CN=Test CA");
            var signingCertificate = CertificateGeneratorHelper
                    .generateEndEntityCertificate(caKeys, caCertificate, signingKeyPair, "CN=Test Signer", null);
            return new CertificateChain(signingCertificate, List.of(signingCertificate, caCertificate));
        }

        private static byte[] hashWithSha256(byte[] message) throws Exception {
            return MessageDigest.getInstance("SHA-256").digest(message);
        }

        private static byte[] signWithJdk(KeyPair keyPair, byte[] message) throws Exception {
            var signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(message);
            return signature.sign();
        }

        private static SignDataResponseDto answerWithSignature(byte[] signature) {
            var result = new SignatureResponseData();
            result.setIdentifier("0");
            result.setData(Base64.getEncoder().encodeToString(signature));
            return new SignDataResponseDto(List.of(result));
        }
    }
}
