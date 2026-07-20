package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CertificateValidationStatusPoller#resolveOrKeep}.
 *
 * <p>An already-resolved DTO status is returned without any DB read. A NOT_CHECKED status is
 * polled (each sample a fresh read) until it resolves or the budget is exhausted; if it never
 * resolves — or the certificate can no longer be found — NOT_CHECKED is returned so the caller
 * decides the fallback.</p>
 */
class CertificateValidationStatusPollerTest {

    private CertificateInternalService certificateService;
    private CertificateValidationStatusPoller poller;

    @BeforeEach
    void setUp() {
        certificateService = mock(CertificateInternalService.class);
        poller = new CertificateValidationStatusPoller();
        poller.setCertificateService(certificateService);
    }

    @Test
    void returnsImmediately_whenDtoAlreadyResolved() throws NotFoundException {
        CertificateDetailDto dto = dto(CertificateValidationStatus.VALID);

        CertificateValidationStatus resolved = poller.resolveOrKeep(dto);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        // Already resolved on the DTO — no DB read at all.
        verify(certificateService, times(0)).getCertificateEntity(any(SecuredUUID.class));
    }

    @Test
    void resolvesToValid_whenValidationLandsDuringWait() throws Exception {
        // Each sample is a fresh read; the poller observes the flip once validation commits.
        CertificateDetailDto dto = dto(CertificateValidationStatus.NOT_CHECKED);
        Certificate entity = entity(CertificateValidationStatus.NOT_CHECKED);
        AtomicInteger reads = new AtomicInteger();
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenAnswer(invocation -> {
                    if (reads.incrementAndGet() >= 2) {
                        entity.setValidationStatus(CertificateValidationStatus.VALID);
                    }
                    return entity;
                });

        // Small budget: the per-sample sleep is clamped to the remaining budget, so the test
        // spends ~budget of wall-clock, not a full sampling interval. The flip is driven by the
        // read count (2nd read), not by elapsed time, so it stays deterministic.
        CertificateValidationStatus resolved = poller.resolveOrKeep(dto, 50L);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        assertThat(reads.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void returnsNotChecked_whenBudgetExhausted() throws Exception {
        // Validation never lands (listener down / backlogged): NOT_CHECKED is returned after
        // the budget, via repeated fresh reads.
        CertificateDetailDto dto = dto(CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenReturn(entity(CertificateValidationStatus.NOT_CHECKED));

        CertificateValidationStatus resolved = poller.resolveOrKeep(dto, 10L);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
        verify(certificateService, atLeast(2)).getCertificateEntity(any(SecuredUUID.class));
    }

    @Test
    void returnsNotChecked_whenCertificateNoLongerFound() throws Exception {
        // The re-read failing to find the entity resolves nothing — keep the transient status.
        CertificateDetailDto dto = dto(CertificateValidationStatus.NOT_CHECKED);
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenThrow(new com.otilm.api.exception.NotFoundException(Certificate.class, dto.getUuid()));

        CertificateValidationStatus resolved = poller.resolveOrKeep(dto);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
    }

    private static CertificateDetailDto dto(CertificateValidationStatus status) {
        CertificateDetailDto dto = new CertificateDetailDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setValidationStatus(status);
        return dto;
    }

    private static Certificate entity(CertificateValidationStatus status) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(status);
        return cert;
    }
}
