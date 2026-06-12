package com.otilm.core.signing.tsa.signer;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignerFactoryTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResolvedManagedScheme anyScheme() {
        return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of());
    }

    @Test
    void returnsSigner_whenCreatorSupportsScheme() throws TspException {
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
    void throwsSystemFailure_whenNoCreatorSupportsScheme() {
        // given — no creator handles the scheme (e.g. an unsupported or misconfigured signing scheme)
        SignerCreator unsupportedCreator = mock(SignerCreator.class);
        when(unsupportedCreator.supports(anyScheme())).thenReturn(false);

        SignerFactory factory = new SignerFactory(List.of(unsupportedCreator));

        // when / then
        assertThatThrownBy(() -> factory.create(anyScheme()))
                .isInstanceOf(TspException.class)
                .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                        .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
    }

    @Test
    void throwsSystemFailure_whenCreatorListIsEmpty() {
        // given
        SignerFactory factory = new SignerFactory(List.of());

        // when / then
        assertThatThrownBy(() -> factory.create(anyScheme()))
                .isInstanceOf(TspException.class)
                .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                        .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
    }

    @Test
    void delegatesToFirstMatchingCreator_whenMultipleCreatorsExist() throws TspException {
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
