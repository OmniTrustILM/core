package com.otilm.core.signing.engine.certificate;

import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SigningCertificateValidatorFactoryTest {

    @Mock
    SigningCertificateValidator supportingProvider;

    @Mock
    SigningCertificateValidator nonSupportingProvider;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResolvedManagedScheme anyScheme() {
        return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of());
    }

    @Test
    void returnsProvider_whenProviderSupportsScheme() throws SigningEngineException {
        // given
        var scheme = anyScheme();
        when(nonSupportingProvider.supports(scheme)).thenReturn(false);
        when(supportingProvider.supports(scheme)).thenReturn(true);
        var factory = new SigningCertificateValidatorFactory(List.of(nonSupportingProvider, supportingProvider));

        // when
        SigningCertificateValidator result = factory.getValidator(scheme);

        // then
        assertThat(result).isSameAs(supportingProvider);
    }

    @Test
    void throwsSigningEngineException_whenNoProviderSupportsScheme() {
        // given
        var scheme = anyScheme();
        when(nonSupportingProvider.supports(scheme)).thenReturn(false);
        var factory = new SigningCertificateValidatorFactory(List.of(nonSupportingProvider));

        // when / then
        assertThatThrownBy(() -> factory.getValidator(scheme))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }
}
