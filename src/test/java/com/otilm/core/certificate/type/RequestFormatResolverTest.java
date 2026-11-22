package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestFormatResolverTest {

    private final RequestFormatResolver resolver = new RequestFormatResolver(
            new CertificateTypeHandlerRegistry(List.of(new X509CertificateTypeHandler())));

    @Test
    void keepsTheRequestedFormat_whenTheClientNamedOne() {
        // given
        CertificateRequestFormat requested = CertificateRequestFormat.CRMF;

        // when
        CertificateRequestFormat resolved = resolver.resolve(requested, CertificateType.X509);

        // then
        assertThat(resolved).isEqualTo(requested);
    }

    @Test
    void returnsTheDefaultOfTheType_whenNoFormatWasNamed() {
        // given — a request without a format for an X.509 certificate

        // when
        CertificateRequestFormat resolved = resolver.resolve(null, CertificateType.X509);

        // then
        assertThat(resolved).isEqualTo(CertificateRequestFormat.PKCS10);
    }

    @Test
    void treatsTheCertificateAsX509_whenNoTypeWasNamed() {
        // given — a request without a format or a type

        // when
        CertificateRequestFormat resolved = resolver.resolve(null, null);

        // then
        assertThat(resolved).isEqualTo(CertificateRequestFormat.PKCS10);
    }

    @Test
    void throwsUnsupportedNamingTheType_whenAnExplicitFormatIsForATypeWithoutAHandler() {
        // given — a request for an SSH certificate that names pkcs10, while only X.509 has a handler
        CertificateRequestFormat explicitFormat = CertificateRequestFormat.PKCS10;

        // when
        ThrowingCallable resolveExplicit = () -> resolver.resolve(explicitFormat, CertificateType.SSH);

        // then
        assertThatThrownBy(resolveExplicit)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(CertificateType.SSH.getCode());
    }

    @Test
    void throwsUnsupportedNamingTheType_whenNoHandlerIsRegisteredForTheType() {
        // given
        var resolverWithoutHandlers = new RequestFormatResolver(new CertificateTypeHandlerRegistry(List.of()));

        // when
        ThrowingCallable resolveDefault = () -> resolverWithoutHandlers.resolve(null, CertificateType.X509);

        // then
        assertThatThrownBy(resolveDefault)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(CertificateType.X509.getCode());
    }
}
