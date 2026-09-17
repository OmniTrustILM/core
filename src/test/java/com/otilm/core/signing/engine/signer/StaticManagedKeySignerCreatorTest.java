package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.builders.RsaSignatureAttributesBuilder;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        void throwsMisconfigured_whenTheSigningAttributesNameNoSignatureAlgorithm() {
            // given — no signing attributes at all, so no digest or RSA scheme can be read for an RSA key
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.MISCONFIGURED);
                        assertThat(((SigningEngineException) ex).operatorMessage())
                                .contains("name no signature algorithm");
                    });
        }

        @Test
        void throwsMisconfigured_whenTheAttributesNameAnUnsupportedSignatureAlgorithm() {
            // given — SHA-1 with RSA resolves to SHA1WITHRSA, outside the SignatureAlgorithm enum
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null,
                    RsaSignatureAttributesBuilder.rsaSignatureAttributes().withDigest(DigestAlgorithm.SHA_1).build());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.MISCONFIGURED);
                        assertThat(((SigningEngineException) ex).operatorMessage())
                                .contains("SHA1WITHRSA", "which the platform does not support");
                        assertThat(((SigningEngineException) ex).clientMessage())
                                .isEqualTo("Signing key algorithm is not supported.");
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

        @ParameterizedTest(name = "{0}")
        @MethodSource("com.otilm.core.signing.engine.signer.StaticManagedKeySignerCreatorTest#postQuantumParameterSets")
        void resolvesThePostQuantumParameterSetToItsConstant(SignatureAlgorithm expected, KeyAlgorithm keyAlgorithm)
                throws SigningEngineException {
            // given
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(keyAlgorithm),
                                    CryptographicKeyItemModelFixtures.publicKey(keyAlgorithm, expected.getCode())),
                    null, List.of());

            // when
            Signer signer = creator.create(scheme);

            // then
            assertThat(signer.getSignatureAlgorithm()).isEqualTo(expected);
        }
    }

    static Stream<Arguments> postQuantumParameterSets() {
        return Stream
                .of(Arguments.of(SignatureAlgorithm.FALCON_1024, KeyAlgorithm.FALCON),
                        Arguments.of(SignatureAlgorithm.ML_DSA_44, KeyAlgorithm.MLDSA),
                        Arguments.of(SignatureAlgorithm.ML_DSA_65, KeyAlgorithm.MLDSA),
                        Arguments.of(SignatureAlgorithm.ML_DSA_87, KeyAlgorithm.MLDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_128S, KeyAlgorithm.SLHDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_128F, KeyAlgorithm.SLHDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_192S, KeyAlgorithm.SLHDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_192F, KeyAlgorithm.SLHDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_256S, KeyAlgorithm.SLHDSA),
                        Arguments.of(SignatureAlgorithm.SLH_DSA_SHA2_256F, KeyAlgorithm.SLHDSA));
    }
}
