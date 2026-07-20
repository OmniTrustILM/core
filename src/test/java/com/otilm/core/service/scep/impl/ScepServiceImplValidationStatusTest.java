package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ScepServiceImpl#checkCertificateValidity}.
 *
 * <p>NOT_CHECKED is a transient state only for the freshly-issued end-entity certificate
 * (tolerateNotChecked=true): its status is resolved through {@link CertificateValidationStatusPoller}
 * and NOT_CHECKED is accepted if it never resolves. CA / issuer certs (tolerateNotChecked=false)
 * are never waited on and must already be VALID/EXPIRING.</p>
 */
class ScepServiceImplValidationStatusTest {

    private ScepServiceImpl service;
    private CertificateValidationStatusPoller validationStatusPoller;

    @BeforeEach
    void setUp() {
        service = new ScepServiceImpl();
        validationStatusPoller = mock(CertificateValidationStatusPoller.class);
        service.setValidationStatusPoller(validationStatusPoller);
    }

    @Test
    void acceptsLeaf_whenResolveOrKeepReturnsValid() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.resolveOrKeep(dto)).thenReturn(CertificateValidationStatus.VALID);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, true))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsLeaf_whenResolveOrKeepReturnsExpiring() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.resolveOrKeep(dto)).thenReturn(CertificateValidationStatus.EXPIRING);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, true))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsLeaf_whenResolveOrKeepReturnsNotChecked() {
        // NOT_CHECKED is a transient state, not a verdict (issue #1834): even if the poller
        // cannot resolve it within the budget, an issuance that already succeeded must not fail.
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.resolveOrKeep(dto)).thenReturn(CertificateValidationStatus.NOT_CHECKED);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, true))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsLeaf_whenResolveOrKeepReturnsInvalid() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.resolveOrKeep(dto)).thenReturn(CertificateValidationStatus.INVALID);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, true))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(ScepException.class)
                .hasMessageContaining("Status: Invalid");
    }

    @Test
    void acceptsCaCertificate_whenValid_withoutWaiting() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.VALID);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, false))
                .doesNotThrowAnyException();

        verifyNoInteractions(validationStatusPoller);
    }

    @Test
    void rejectsCaCertificate_whenNotChecked() {
        // Security (PR #1839 review): the NOT_CHECKED tolerance is ONLY for the freshly-issued
        // leaf (tolerateNotChecked=false here). A CA / issuer cert that is still NOT_CHECKED
        // must be rejected, not waited on.
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto, false))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(ScepException.class)
                .hasMessageContaining("Status: Not checked");

        verifyNoInteractions(validationStatusPoller);
    }

    private static CertificateDetailDto certificateDto(CertificateValidationStatus status) {
        CertificateDetailDto dto = new CertificateDetailDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setFingerprint("aa:bb:cc");
        dto.setValidationStatus(status);
        return dto;
    }
}
