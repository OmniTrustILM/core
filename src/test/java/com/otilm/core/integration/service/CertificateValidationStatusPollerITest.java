package com.otilm.core.integration.service;

import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CMP and SCEP handlers wait for a fresh certificate's validation with no transaction of their own, while the
 * request's EntityManager, bound by open-in-view, already holds the certificate as it was when the chain was loaded.
 */
class CertificateValidationStatusPollerITest extends BaseSpringBootTest {

    private static final long VALIDATION_DELAY_MS = 300L;

    @Autowired
    private CertificateValidationStatusPoller poller;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private EntityManager requestEntityManager;

    @BeforeEach
    void bindRequestEntityManager() {
        requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
    }

    @AfterEach
    void unbindRequestEntityManager() {
        TransactionSynchronizationManager.unbindResource(entityManagerFactory);
        requestEntityManager.close();
    }

    @Test
    void returnsStatusCommittedMeanwhile_whenTheRequestHoldsTheCertificate() {
        // given
        UUID certificateUuid = seedCertificateNotYetValidated();
        Certificate heldByRequest = requestEntityManager.find(Certificate.class, certificateUuid);
        CertificateDetailDto issued = detailOf(heldByRequest);
        CompletableFuture<Void> validationLands = markValidAfter(certificateUuid, VALIDATION_DELAY_MS);

        // when
        long start = System.nanoTime();
        CertificateValidationStatus resolved = poller.resolveOrKeep(issued);
        Duration waited = Duration.ofNanos(System.nanoTime() - start);

        // then
        validationLands.join();
        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
        assertThat(waited).isLessThan(Duration.ofSeconds(2));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID seedCertificateNotYetValidated() {
        Certificate certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withState(CertificateState.ISSUED)
                .withValidationStatus(CertificateValidationStatus.NOT_CHECKED)
                .build();
        return certificateRepository.save(certificate).getUuid();
    }

    private CompletableFuture<Void> markValidAfter(UUID certificateUuid, long delayMs) {
        Executor delayed = CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS);
        TransactionTemplate validationTransaction = new TransactionTemplate(transactionManager);
        return CompletableFuture.runAsync(() -> validationTransaction.executeWithoutResult(status -> {
            Certificate validated = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            validated.setValidationStatus(CertificateValidationStatus.VALID);
        }), delayed);
    }

    private static CertificateDetailDto detailOf(Certificate certificate) {
        CertificateDetailDto detail = new CertificateDetailDto();
        detail.setUuid(certificate.getUuid().toString());
        detail.setValidationStatus(certificate.getValidationStatus());
        return detail;
    }
}
