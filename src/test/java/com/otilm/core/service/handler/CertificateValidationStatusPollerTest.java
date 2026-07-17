package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CertificateValidationStatusPoller#pollValidationStatus}.
 *
 * <p>Validation is advanced asynchronously (event-driven after issuance, hourly batch as
 * fallback). The poller waits briefly for a NOT_CHECKED certificate to resolve so a caller
 * can catch a definitively bad status, and hands back NOT_CHECKED when the budget is
 * exhausted so the caller decides the fallback.</p>
 */
class CertificateValidationStatusPollerTest {

    private CertificateInternalService certificateService;
    private EntityManager entityManager;
    private CertificateValidationStatusPoller poller;

    @BeforeEach
    void setUp() {
        certificateService = Mockito.mock(CertificateInternalService.class);
        entityManager = Mockito.mock(EntityManager.class);
        poller = new CertificateValidationStatusPoller();
        poller.setCertificateService(certificateService);
        ReflectionTestUtils.setField(poller, "entityManager", entityManager);
    }

    @Test
    void returnsImmediately_whenAlreadyResolved() throws Exception {
        Certificate cert = certificateInState(CertificateValidationStatus.VALID);
        Mockito.when(certificateService.getCertificateEntity(Mockito.any(SecuredUUID.class)))
                .thenReturn(cert);

        CertificateValidationStatus resolved = poller.pollValidationStatus(UUID.randomUUID().toString(), 3_000L);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        Mockito.verify(entityManager, Mockito.never()).refresh(Mockito.any());
    }

    @Test
    void waitsForAsyncValidation_andReturnsResolvedStatus() throws Exception {
        // The event-driven post-issuance validation lands on the validationListener thread
        // moments after ISSUED; the wait must observe the flip via refresh instead of
        // giving up on the first NOT_CHECKED read.
        Certificate cert = certificateInState(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateEntity(Mockito.any(SecuredUUID.class)))
                .thenReturn(cert);
        AtomicInteger refreshes = new AtomicInteger();
        Mockito.doAnswer(invocation -> {
            if (refreshes.incrementAndGet() >= 2) {
                cert.setValidationStatus(CertificateValidationStatus.VALID);
            }
            return null;
        }).when(entityManager).refresh(cert);

        CertificateValidationStatus resolved = poller.pollValidationStatus(UUID.randomUUID().toString(), 3_000L);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        assertThat(refreshes.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void returnsNotChecked_whenBudgetExhausted() throws Exception {
        // Validation never lands (listener down / backlogged): the caller gets NOT_CHECKED
        // back after the budget and decides the fallback itself.
        Certificate cert = certificateInState(CertificateValidationStatus.NOT_CHECKED);
        Mockito.when(certificateService.getCertificateEntity(Mockito.any(SecuredUUID.class)))
                .thenReturn(cert);

        CertificateValidationStatus resolved = poller.pollValidationStatus(UUID.randomUUID().toString(), 600L);

        assertThat(resolved).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
        Mockito.verify(entityManager, Mockito.atLeast(1)).refresh(cert);
    }

    private static Certificate certificateInState(CertificateValidationStatus status) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(CertificateState.ISSUED);
        cert.setSerialNumber("01");
        cert.setValidationStatus(status);
        return cert;
    }
}
