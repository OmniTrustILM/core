package com.czertainly.core.signing.tsa.certificate;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SigningCertificateValidatorFactoryTest {

    @Mock
    SigningCertificateValidator supportingProvider;

    @Mock
    SigningCertificateValidator nonSupportingProvider;

    private static ResolvedManagedScheme anyScheme() {
        return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of());
    }

    // ── getValidator() ─────────────────────────────────────────────────────────

    @Test
    void getValidator_returnsProvider_whenProviderSupportsScheme() throws TspException {
        // given
        var scheme = anyScheme();
        when(nonSupportingProvider.supports(scheme)).thenReturn(false);
        when(supportingProvider.supports(scheme)).thenReturn(true);
        var factory = new SigningCertificateValidatorFactory(List.of(nonSupportingProvider, supportingProvider));

        // when
        SigningCertificateValidator result = factory.getValidator(scheme);

        // then
        assertSame(supportingProvider, result);
    }

    @Test
    void getValidator_throwsTspException_whenNoProviderSupportsScheme() {
        // given
        var scheme = anyScheme();
        when(nonSupportingProvider.supports(scheme)).thenReturn(false);
        var factory = new SigningCertificateValidatorFactory(List.of(nonSupportingProvider));

        // when / then
        var exception = assertThrows(TspException.class, () -> factory.getValidator(scheme));
        assertEquals(TspFailureInfo.SYSTEM_FAILURE, exception.getFailureInfo());
    }
}
