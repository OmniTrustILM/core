package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.UUID;
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
        void throwsMisconfigured_carryingTheProvidersReason_whenNoAlgorithmIsNamed() throws Exception {
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
                                .isEqualTo("Signing key algorithm is not supported.");
                    });
        }

        @Test
        void throwsConnectorFault_whenTheProviderCannotBeReached() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new ConnectorException("provider unreachable"));

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                        assertThat(((SigningEngineException) ex).operatorMessage()).contains("provider unreachable");
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
        void throwsMisconfigured_whenTheKeyHasNoOperationScope() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willThrow(new NotFoundException(CryptographicKey.class, UUID.randomUUID()));

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

        /** Whatever the provider names is what the signer carries; the creator adds no opinion of its own. */
        @Test
        void carriesTheAlgorithmTheProviderNames() throws Exception {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA),
                                    CryptographicKeyItemModelFixtures
                                            .publicKey(KeyAlgorithm.MLDSA, SignatureAlgorithm.ML_DSA_65.getCode())),
                    null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willReturn(SignatureAlgorithm.ML_DSA_65);

            // when
            Signer signer = creator.create(scheme);

            // then
            assertThat(signer.getSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.ML_DSA_65);
        }

        /** The public key item is what carries a PQC parameter set, so the provider is told which one it is. */
        @Test
        void passesBothKeyItemsAndTheAttributesToTheProvider() throws Exception {
            // given
            var privateKey = CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA);
            var publicKey = CryptographicKeyItemModelFixtures
                    .publicKey(KeyAlgorithm.MLDSA, SignatureAlgorithm.ML_DSA_65.getCode());
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(), List.of(privateKey, publicKey), null, List.of());
            given(cryptographicOperationService.resolveSignatureAlgorithm(any(), any(), anyList()))
                    .willReturn(SignatureAlgorithm.ML_DSA_65);

            // when
            creator.create(scheme);

            // then
            then(cryptographicOperationService).should().resolveSignatureAlgorithm(privateKey, publicKey, List.of());
        }

    }
}
