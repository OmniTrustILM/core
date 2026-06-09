package com.czertainly.core.signing.tsa.certificate;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

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
    void returnsProvider_whenProviderSupportsScheme() throws TspException {
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
    void throwsTspException_whenNoProviderSupportsScheme() {
        // given
        var scheme = anyScheme();
        when(nonSupportingProvider.supports(scheme)).thenReturn(false);
        var factory = new SigningCertificateValidatorFactory(List.of(nonSupportingProvider));

        // when / then
        assertThatThrownBy(() -> factory.getValidator(scheme))
                .isInstanceOf(TspException.class)
                .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                        .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
    }
}
