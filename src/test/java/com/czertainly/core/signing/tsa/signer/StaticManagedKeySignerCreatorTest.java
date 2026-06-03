package com.czertainly.core.signing.tsa.signer;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.service.CryptographicOperationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class StaticManagedKeySignerCreatorTest {

    @Mock
    private CryptographicOperationService cryptographicOperationService;

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
        void throwsSystemFailure_whenCertificateHasNoKey() {
            // given — the certificate is not backed by a managed cryptographic key (no key UUID)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.aSigningCertificate().withoutKey().build(), List.of(), null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenKeyHasNoPrivateKeyItem() {
            // given — the key only holds a public key item (no private key to sign with)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List.of(CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)),
                    null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenKeyHasNoPublicKeyItem() {
            // given — only a private (RSA) key item is present; the signer still requires a public key item
            // even for classical algorithms, so this must fail (regression guard for the record-based path)
            ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                    SigningCertificateBuilder.valid(),
                    List.of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA)),
                    null, List.of());

            // when / then
            assertThatThrownBy(() -> creator.create(scheme))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }
    }
}
