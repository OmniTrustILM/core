package com.otilm.core.certificate.type;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.certificate.type.stub.StubCertificateTypeHandler;
import com.otilm.core.dao.entity.Certificate;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static com.otilm.core.util.RestrictedTypeHandlerFixtures.registryWithX509Lacking;
import static com.otilm.core.util.StubCertificateFixtures.certificate;
import static com.otilm.core.util.StubCertificateFixtures.request;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateTypeHandlerRegistryTest {

    private static final String UNKNOWN_TYPE = "HOLOGRAM";

    private final StubCertificateTypeHandler stub = new StubCertificateTypeHandler();

    @Test
    void returnsTheHandler_whenRequiringARegisteredType() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));

        // when
        CertificateTypeHandler handler = registry.require(StubCertificateTypeHandler.TYPE_CODE);

        // then
        assertThat(handler).isSameAs(stub);
    }

    @Test
    void throwsUnsupportedNamingTheType_whenRequiringAnUnknownType() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));

        // when
        ThrowingCallable requireUnknown = () -> registry.require(UNKNOWN_TYPE);

        // then
        assertThatThrownBy(requireUnknown)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(UNKNOWN_TYPE);
    }

    @Test
    void throwsUnsupportedNamingTheOperation_whenTheTypeOfTheCertificateDoesNotSupportIt() {
        // given
        var unsupported = CertificateOperation.REVOKE;
        var registry = registryWithX509Lacking(new X509CertificateTypeHandler(), unsupported);
        Certificate certificate = aCertificate().build();

        // when
        ThrowingCallable require = () -> registry.requireSupport(certificate, unsupported);

        // then
        assertThatThrownBy(require)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(unsupported.getLabel())
                .hasMessageContaining(CertificateType.X509.getCode());
    }

    @Test
    void supportsTheOperation_whenTheTypeOfTheCertificateDeclaresIt() {
        // given
        var registry = registryWithX509Lacking(new X509CertificateTypeHandler(), CertificateOperation.REVOKE);
        Certificate certificate = aCertificate().build();

        // when
        boolean supported = registry.supports(certificate, CertificateOperation.RENEW);

        // then
        assertThat(supported).isTrue();
    }

    @Test
    void supportsNoOperation_whenTheTypeOfTheCertificateHasNoHandler() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));
        Certificate certificate = aCertificate().build();

        // when
        boolean supported = registry.supports(certificate, CertificateOperation.VALIDATE);

        // then
        assertThat(supported).isFalse();
    }

    @Test
    void returnsEmpty_whenFindingAnUnknownType() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));

        // when
        Optional<CertificateTypeHandler> handler = registry.find(UNKNOWN_TYPE);

        // then
        assertThat(handler).isEmpty();
    }

    @Test
    void detectsTheTypeAndReadsTheCertificate_whenTheContentIsOfARegisteredType() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));
        byte[] stubCertificate = certificate("42", "holder-one");

        // when
        Optional<CertificateTypeHandlerRegistry.DetectedCertificate> detected = registry
                .detectCertificate(stubCertificate);

        // then
        assertThat(detected).isPresent();
        assertThat(detected.get().handler()).isSameAs(stub);
        assertThat(detected.get().certificate().typeCode()).isEqualTo(StubCertificateTypeHandler.TYPE_CODE);
        assertThat(detected.get().certificate().properties().identifier()).isEqualTo("42");
    }

    @Test
    void detectsNothing_whenNoHandlerRecognisesTheCertificateContent() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));
        byte[] notACertificate = "not a certificate".getBytes(StandardCharsets.UTF_8);

        // when
        Optional<CertificateTypeHandlerRegistry.DetectedCertificate> detected = registry
                .detectCertificate(notACertificate);

        // then
        assertThat(detected).isEmpty();
    }

    @Test
    void detectsTheTypeAndReadsTheRequest_whenTheContentIsOfARegisteredType() {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(stub));
        byte[] stubRequest = request("holder-one", true, "42");

        // when
        Optional<CertificateTypeHandlerRegistry.DetectedRequest> detected = registry.detectRequest(stubRequest);

        // then
        assertThat(detected).isPresent();
        assertThat(detected.get().handler()).isSameAs(stub);
        assertThat(detected.get().request().holder()).isEqualTo("holder-one");
    }

    @Test
    void throwsIllegalState_whenTwoHandlersClaimTheSameType() {
        // given
        var duplicate = new StubCertificateTypeHandler();

        // when
        ThrowingCallable register = () -> new CertificateTypeHandlerRegistry(List.of(stub, duplicate));

        // then
        assertThatThrownBy(register)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(StubCertificateTypeHandler.TYPE_CODE);
    }

    @Test
    void resolvesTheHandler_whenItIsRegisteredAsABean() {
        // given
        try (var context = new AnnotationConfigApplicationContext()) {
            context.register(CertificateTypeHandlerRegistry.class, StubCertificateTypeHandler.class);
            context.refresh();

            // when
            CertificateTypeHandler handler = context
                    .getBean(CertificateTypeHandlerRegistry.class)
                    .require(StubCertificateTypeHandler.TYPE_CODE);

            // then
            assertThat(handler).isInstanceOf(StubCertificateTypeHandler.class);
        }
    }
}
