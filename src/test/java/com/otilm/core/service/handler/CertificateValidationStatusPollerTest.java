package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.repository.CertificateRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CertificateValidationStatusPoller#resolveOrKeep}. Open-in-view freshness of the reads is
 * covered by {@code CertificateValidationStatusPollerITest}.
 */
@ExtendWith(MockitoExtension.class)
class CertificateValidationStatusPollerTest {

    @Mock
    private CertificateRepository certificateRepository;

    private CertificateValidationStatusPoller poller;

    @BeforeEach
    void wirePoller() {
        poller = new CertificateValidationStatusPoller();
        poller.setCertificateRepository(certificateRepository);
    }

    @Test
    void returnsTheDtoStatusWithoutReading_whenAlreadyResolved() {
        // given
        CertificateDetailDto alreadyValid = detail(CertificateValidationStatus.VALID);

        // when
        CertificateValidationStatus resolved = poller.resolveOrKeep(alreadyValid);

        // then
        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        verifyNoInteractions(certificateRepository);
    }

    @Test
    void returnsValid_whenValidationLandsDuringTheWait() {
        // given
        CertificateDetailDto notYetChecked = detail(CertificateValidationStatus.NOT_CHECKED);
        when(certificateRepository.findValidationStatusByUuid(any(UUID.class)))
                .thenReturn(Optional.of(CertificateValidationStatus.NOT_CHECKED))
                .thenReturn(Optional.of(CertificateValidationStatus.VALID));

        // when
        CertificateValidationStatus resolved = poller.resolveOrKeep(notYetChecked, 1_000L);

        // then
        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
    }

    @Test
    void returnsNotChecked_whenTheBudgetRunsOut() {
        // given
        CertificateDetailDto notYetChecked = detail(CertificateValidationStatus.NOT_CHECKED);
        when(certificateRepository.findValidationStatusByUuid(any(UUID.class)))
                .thenReturn(Optional.of(CertificateValidationStatus.NOT_CHECKED));

        // when
        CertificateValidationStatus resolved = poller.resolveOrKeep(notYetChecked, 10L);

        // then
        assertThat(resolved).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
        verify(certificateRepository, atLeast(2)).findValidationStatusByUuid(any(UUID.class));
    }

    @Test
    void returnsNotChecked_whenTheCertificateIsGone() {
        // given
        CertificateDetailDto notYetChecked = detail(CertificateValidationStatus.NOT_CHECKED);
        when(certificateRepository.findValidationStatusByUuid(any(UUID.class))).thenReturn(Optional.empty());

        // when
        CertificateValidationStatus resolved = poller.resolveOrKeep(notYetChecked);

        // then
        assertThat(resolved).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CertificateDetailDto detail(CertificateValidationStatus status) {
        CertificateDetailDto detail = new CertificateDetailDto();
        detail.setUuid(UUID.randomUUID().toString());
        detail.setValidationStatus(status);
        return detail;
    }
}
