package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ScepServiceImpl#checkCertificateValidity} (issue #1834).
 *
 * <p>A certificate that just reached CertificateState.ISSUED can still have
 * CertificateValidationStatus.NOT_CHECKED — validation is advanced asynchronously
 * (event-driven after issuance, hourly batch as fallback). NOT_CHECKED is a transient
 * state, not a verdict: the SCEP success path waits briefly for the in-flight validation
 * to land (so a definitively bad status is still caught) and accepts NOT_CHECKED if it
 * doesn't — the response must reflect issuance success, never fail on validation
 * progress.</p>
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
    void doesNotWait_whenCertificateAlreadyValid() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.VALID);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .doesNotThrowAnyException();

        verifyNoInteractions(validationStatusPoller);
    }

    @Test
    void doesNotWait_whenCertificateExpiring() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.EXPIRING);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .doesNotThrowAnyException();

        verifyNoInteractions(validationStatusPoller);
    }

    @Test
    void accepts_whenAsyncValidationResolvesToValidDuringWait() throws NotFoundException {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.pollValidationStatus(eq(dto.getUuid()), anyLong()))
                .thenReturn(CertificateValidationStatus.VALID);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .doesNotThrowAnyException();
    }

    @Test
    void accepts_whenStillNotCheckedAfterWait() throws NotFoundException {
        // NOT_CHECKED is a transient state, not a verdict (issue #1834 expected behavior):
        // even if the validation never lands within the wait budget, the enrollment whose
        // issuance succeeded must not be failed.
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.pollValidationStatus(eq(dto.getUuid()), anyLong()))
                .thenReturn(CertificateValidationStatus.NOT_CHECKED);

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .doesNotThrowAnyException();
    }

    @Test
    void rejects_whenWaitResolvesToInvalid() throws NotFoundException {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.pollValidationStatus(eq(dto.getUuid()), anyLong()))
                .thenReturn(CertificateValidationStatus.INVALID);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(ScepException.class)
                .hasMessageContaining("Status: Invalid");
    }

    @Test
    void rejects_whenCertificateDefinitivelyRevoked() {
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.REVOKED);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(ScepException.class)
                .hasMessageContaining("Status: Revoked");

        verifyNoInteractions(validationStatusPoller);
    }

    @Test
    void accepts_whenEntityNoLongerFoundDuringWait() throws NotFoundException {
        // The wait failing to find the entity resolves nothing — the status stays
        // NOT_CHECKED, which is transient, so the certificate passes.
        CertificateDetailDto dto = certificateDto(CertificateValidationStatus.NOT_CHECKED);
        when(validationStatusPoller.pollValidationStatus(eq(dto.getUuid()), anyLong()))
                .thenThrow(new NotFoundException(Certificate.class, dto.getUuid()));

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkCertificateValidity", dto))
                .doesNotThrowAnyException();
    }

    private static CertificateDetailDto certificateDto(CertificateValidationStatus status) {
        CertificateDetailDto dto = new CertificateDetailDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setFingerprint("aa:bb:cc");
        dto.setValidationStatus(status);
        return dto;
    }
}
