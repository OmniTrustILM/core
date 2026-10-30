package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignerFactoryTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResolvedManagedScheme anyScheme() {
        return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of());
    }

    @Test
    void returnsSigner_whenCreatorSupportsScheme() throws SigningEngineException {
        // given
        ResolvedManagedScheme scheme = anyScheme();
        Signer expectedSigner = mock(Signer.class);
        SignerCreator creator = mock(SignerCreator.class);
        when(creator.supports(scheme)).thenReturn(true);
        when(creator.create(scheme)).thenReturn(expectedSigner);

        SignerFactory factory = new SignerFactory(List.of(creator));

        // when
        Signer result = factory.create(scheme);

        // then
        assertThat(result).isSameAs(expectedSigner);
        verify(creator).create(scheme);
    }

    @Test
    void answersTheAlgorithmTheSchemesSignerWouldUse() throws SigningEngineException {
        // given
        ResolvedManagedScheme scheme = anyScheme();
        Signer signer = mock(Signer.class);
        when(signer.getSignatureAlgorithm()).thenReturn(SignatureAlgorithm.SHA256_WITH_RSA_PSS);
        SignerCreator creator = mock(SignerCreator.class);
        when(creator.supports(scheme)).thenReturn(true);
        when(creator.create(scheme)).thenReturn(signer);

        SignerFactory factory = new SignerFactory(List.of(creator));

        // when
        SignatureAlgorithm algorithm = factory.signatureAlgorithm(scheme);

        // then
        assertThat(algorithm).isEqualTo(SignatureAlgorithm.SHA256_WITH_RSA_PSS);
        verify(signer, never()).sign(any());
    }

    @Test
    void throwsMisconfigured_whenNoCreatorSupportsScheme() {
        // given — no creator handles the scheme (e.g. an unsupported or misconfigured signing scheme)
        SignerCreator unsupportedCreator = mock(SignerCreator.class);
        when(unsupportedCreator.supports(anyScheme())).thenReturn(false);

        SignerFactory factory = new SignerFactory(List.of(unsupportedCreator));

        // when / then
        assertThatThrownBy(() -> factory.create(anyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void throwsMisconfigured_whenCreatorListIsEmpty() {
        // given
        SignerFactory factory = new SignerFactory(List.of());

        // when / then
        assertThatThrownBy(() -> factory.create(anyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void delegatesToFirstMatchingCreator_whenMultipleCreatorsExist() throws SigningEngineException {
        // given — second creator matches but first one is checked first
        ResolvedManagedScheme scheme = anyScheme();
        Signer expectedSigner = mock(Signer.class);

        SignerCreator first = mock(SignerCreator.class);
        when(first.supports(scheme)).thenReturn(true);
        when(first.create(scheme)).thenReturn(expectedSigner);

        SignerCreator second = mock(SignerCreator.class);
        when(second.supports(scheme)).thenReturn(true);

        SignerFactory factory = new SignerFactory(List.of(first, second));

        // when
        Signer result = factory.create(scheme);

        // then — only the first matching creator was used
        assertThat(result).isSameAs(expectedSigner);
        verify(first).create(scheme);
    }
}
