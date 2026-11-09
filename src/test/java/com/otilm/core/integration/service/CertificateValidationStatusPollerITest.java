package com.otilm.core.integration.service;

import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
import com.otilm.core.util.BaseSpringBootTest;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.sql.DataSource;
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
 * The CMP handler waits for a fresh certificate's validation with no transaction, while the request's EntityManager,
 * bound by open-in-view, already holds the certificate as it was when the chain was loaded. The SCEP handler waits from
 * inside its own transaction.
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
    @Autowired
    private DataSource dataSource;

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

    @Test
    void returnsStatusCommittedMeanwhile_whenTheCallerHoldsATransaction() {
        // given — SCEP waits from inside its own transaction
        UUID certificateUuid = seedCertificateNotYetValidated();
        CompletableFuture<Void> validationLands = markValidAfter(certificateUuid, VALIDATION_DELAY_MS);
        TransactionTemplate callerTransaction = new TransactionTemplate(transactionManager);

        // when
        CertificateValidationStatus resolved = callerTransaction
                .execute(status -> poller
                        .resolveOrKeep(detailOf(requestEntityManager.find(Certificate.class, certificateUuid))));

        // then
        validationLands.join();
        assertThat(resolved).isEqualTo(CertificateValidationStatus.VALID);
    }

    @Test
    void holdsNoSecondConnectionBetweenSamples_whenTheCallerHoldsATransaction() throws Exception {
        // given — validation never lands, so the wait runs its whole budget
        UUID certificateUuid = seedCertificateNotYetValidated();
        HikariPoolMXBean pool = dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean();
        TransactionTemplate callerTransaction = new TransactionTemplate(transactionManager);

        // when
        ConnectionCounts counts = callerTransaction.execute(status -> {
            CertificateDetailDto unchecked = detailOf(requestEntityManager.find(Certificate.class, certificateUuid));
            long heldByTheCaller = pool.getActiveConnections();
            ActiveConnectionWatch watch = ActiveConnectionWatch.startAfterFirstSample(pool);
            try {
                poller.resolveOrKeep(unchecked);
            } finally {
                watch.stop();
            }
            return new ConnectionCounts(heldByTheCaller, watch.fewest());
        });

        // then
        assertThat(counts.fewestDuringTheWait())
                .as("connections checked out between samples")
                .isEqualTo(counts.heldByTheCaller());
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

    /** Checked-out connections when the wait began, and the fewest seen between its samples. */
    private record ConnectionCounts(long heldByTheCaller, long fewestDuringTheWait) {
    }

    /**
     * Samples the pool's checked-out connections every 50 ms, starting once the wait has taken its first sample, and
     * keeps the fewest seen. The caller's transaction holds one connection throughout; a sample's own short read adds a
     * second only for that read.
     */
    private static final class ActiveConnectionWatch {

        private static final long FIRST_SAMPLE_TAKEN_MS = 500L;

        private final ScheduledExecutorService sampler = Executors.newSingleThreadScheduledExecutor();
        private final AtomicLong fewestSeen = new AtomicLong(Long.MAX_VALUE);
        private ScheduledFuture<?> sampling;

        static ActiveConnectionWatch startAfterFirstSample(HikariPoolMXBean pool) {
            ActiveConnectionWatch watch = new ActiveConnectionWatch();
            watch.sampling = watch.sampler
                    .scheduleAtFixedRate(
                            () -> watch.fewestSeen.accumulateAndGet(pool.getActiveConnections(), Math::min),
                            FIRST_SAMPLE_TAKEN_MS, 50L, TimeUnit.MILLISECONDS);
            return watch;
        }

        void stop() {
            sampling.cancel(false);
            sampler.shutdownNow();
        }

        long fewest() {
            return fewestSeen.get();
        }
    }
}
