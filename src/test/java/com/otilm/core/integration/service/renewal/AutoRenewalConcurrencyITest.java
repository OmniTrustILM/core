package com.otilm.core.integration.service.renewal;

import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.renewal.auto.AutoRenewalAction;
import com.otilm.core.service.renewal.auto.AutoRenewalException;
import com.otilm.core.service.renewal.auto.AutoRenewalHandler;
import com.otilm.core.service.renewal.auto.RenewalContext;
import com.otilm.core.service.renewal.auto.TriggerContext;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class AutoRenewalConcurrencyITest extends BaseSpringBootTest {

    private static final long WAIT_SECONDS = 20;

    @Autowired
    private AutoRenewalSeeder seeder;
    @Autowired
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateEventHistoryInternalService eventHistoryService;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;

    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private final TriggerContext trigger = new TriggerContext(UUID.randomUUID(), UUID.randomUUID(), null, null);
    private Certificate certificate;

    @BeforeEach
    void seedDueCertificate() {
        certificate = seeder.seedDueHeldKeyCertificate(seeder.seedRaProfile(true));
    }

    @AfterEach
    void stopExecutor() {
        executor.shutdownNow();
    }

    @Test
    void startsOneRenewal_whenTwoFiringsRunConcurrently() throws Exception {
        // given
        BlockingHandler handler = new BlockingHandler();
        AutoRenewalAction action = actionWith(handler);
        CyclicBarrier bothReady = new CyclicBarrier(2);

        // when
        List<Future<?>> firings = List
                .of(executor.submit(() -> fireAfter(bothReady, action)),
                        executor.submit(() -> fireAfter(bothReady, action)));
        assertThat(handler.entered.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
        awaitOneDone(firings);
        handler.release.countDown();
        for (Future<?> firing : firings) {
            firing.get(WAIT_SECONDS, TimeUnit.SECONDS);
        }

        // then
        assertThat(handler.calls.get()).isEqualTo(1);
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNull();
    }

    @Test
    void startsTheNextRenewal_whenTheInFlightMarkerHasExpired() throws Exception {
        // given
        BlockingHandler handler = new BlockingHandler();
        handler.release.countDown();
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        row.setRenewStartedAt(Instant.now().minus(Duration.ofMinutes(16)));
        renewalInfoRepository.save(row);

        // when
        actionWith(handler).perform(certificate, trigger);

        // then
        assertThat(handler.calls.get()).isEqualTo(1);
        assertThat(handler.ownerUuid).isEqualTo(trigger.ownerUuid());
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNull();
    }

    @Test
    void skips_whenAnUnexpiredInFlightMarkerIsStored() throws Exception {
        // given
        BlockingHandler handler = new BlockingHandler();
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        Instant claimedByAnotherNode = Instant.now().minus(Duration.ofMinutes(5));
        row.setRenewStartedAt(claimedByAnotherNode);
        renewalInfoRepository.save(row);

        // when
        actionWith(handler).perform(certificate, trigger);

        // then
        assertThat(handler.calls.get()).isZero();
        assertThat(seeder.renewalRow(certificate.getUuid()).getRenewStartedAt()).isNotNull();
    }

    @Test
    void countsAnAttemptAndReleasesTheMarker_whenTheHandlerFails() {
        // given
        AutoRenewalHandler failing = new AutoRenewalHandler() {
            @Override
            public AutoRenewalMode mode() {
                return AutoRenewalMode.ILM_KEY;
            }

            @Override
            public void renew(Certificate renewed, RenewalContext context) throws AutoRenewalException {
                throw new AutoRenewalException("authority unavailable");
            }
        };
        Instant before = Instant.now();

        // when
        ThrowingCallable fire = () -> actionWith(failing).perform(certificate, trigger);

        // then
        assertThatThrownBy(fire).isInstanceOf(RuleException.class).hasMessageContaining("authority unavailable");
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewAttempt()).isEqualTo(1);
        assertThat(stored.getRenewNotBefore()).isAfterOrEqualTo(before.plus(Duration.ofHours(1)));
        assertThat(stored.getRenewStartedAt()).isNull();
    }

    @Test
    void recordsARejectedSuccessorOnce_whenTheNextFiringsFindIt() throws Exception {
        // given
        BlockingHandler handler = new BlockingHandler();
        handler.release.countDown();
        Certificate rejected = seeder.seedSuccessor(certificate.getRaProfile(), CertificateState.REJECTED);
        CertificateRenewalInfo row = seeder.renewalRow(certificate.getUuid());
        row.setRenewSuccessorUuid(rejected.getUuid());
        renewalInfoRepository.save(row);
        AutoRenewalAction action = actionWith(handler);

        // when
        ThrowingCallable firstFiring = () -> action.perform(certificate, trigger);
        assertThatThrownBy(firstFiring).isInstanceOf(RuleException.class).hasMessageContaining("rejected");
        action.perform(certificate, trigger);

        // then
        CertificateRenewalInfo stored = seeder.renewalRow(certificate.getUuid());
        assertThat(stored.getRenewAttempt()).isEqualTo(1);
        assertThat(stored.getRenewSuccessorUuid()).isNull();
        assertThat(handler.calls.get()).isZero();
    }

    @Test
    void recordsAFailureWithoutWaiting_whenTheHandlerMeetsARowTheSuspendedTransactionLocked() throws Exception {
        // given
        UUID certificateUuid = certificate.getUuid();
        AutoRenewalHandler lockingCertificate = new AutoRenewalHandler() {
            @Override
            public AutoRenewalMode mode() {
                return AutoRenewalMode.ILM_KEY;
            }

            @Override
            public void renew(Certificate renewed, RenewalContext context) {
                TransactionTemplate own = new TransactionTemplate(transactionManager);
                own.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
                own.executeWithoutResult(status -> {
                    entityManager.createNativeQuery("SET LOCAL lock_timeout = '1s'").executeUpdate();
                    entityManager.find(Certificate.class, certificateUuid, LockModeType.PESSIMISTIC_WRITE);
                });
            }
        };
        TransactionTemplate evaluation = new TransactionTemplate(transactionManager);

        // when
        Future<Throwable> firing = executor.submit(() -> evaluation.execute(status -> {
            entityManager.find(Certificate.class, certificateUuid, LockModeType.PESSIMISTIC_WRITE);
            try {
                actionWith(lockingCertificate).perform(certificate, trigger);
                return null;
            } catch (RuleException e) {
                return e;
            }
        }));
        Throwable recorded = awaitWithoutHanging(firing);

        // then
        assertThat(recorded).isInstanceOf(RuleException.class);
        CertificateRenewalInfo stored = seeder.renewalRow(certificateUuid);
        assertThat(stored.getRenewAttempt()).isEqualTo(1);
        assertThat(stored.getRenewStartedAt()).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Waits for a firing that may block on a lock its own thread holds. On timeout the waiting statement is cancelled,
     * so the firing ends and the test fails instead of hanging the test JVM.
     */
    private Throwable awaitWithoutHanging(Future<Throwable> firing) throws Exception {
        try {
            return firing.get(60, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            new TransactionTemplate(transactionManager)
                    .executeWithoutResult(status -> entityManager
                            .createNativeQuery("SELECT pg_cancel_backend(pid) FROM pg_stat_activity"
                                    + " WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid()")
                            .getResultList());
            firing.get(WAIT_SECONDS, TimeUnit.SECONDS);
            throw new AssertionError("The renewal waited for a lock its own thread holds", e);
        }
    }

    private AutoRenewalAction actionWith(AutoRenewalHandler handler) {
        return new AutoRenewalAction(renewalInfoRepository, certificateRepository, eventHistoryService, entityManager,
                transactionManager, typeHandlerRegistry, List.of(handler));
    }

    private Void fireAfter(CyclicBarrier barrier, AutoRenewalAction action) throws Exception {
        barrier.await(WAIT_SECONDS, TimeUnit.SECONDS);
        action.perform(certificate, trigger);
        return null;
    }

    private static void awaitOneDone(List<Future<?>> firings) {
        await()
                .atMost(WAIT_SECONDS, TimeUnit.SECONDS)
                .pollInterval(20, TimeUnit.MILLISECONDS)
                .until(() -> firings.stream().anyMatch(Future::isDone));
    }

    /** Renews by holding the firing until released, so a concurrent firing meets the in-flight marker. */
    private static final class BlockingHandler implements AutoRenewalHandler {

        private final AtomicInteger calls = new AtomicInteger();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile UUID ownerUuid;

        @Override
        public AutoRenewalMode mode() {
            return AutoRenewalMode.ILM_KEY;
        }

        @Override
        public void renew(Certificate renewed, RenewalContext context) throws AutoRenewalException {
            calls.incrementAndGet();
            ownerUuid = context.ownerUuid();
            entered.countDown();
            try {
                if (!release.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
                    throw new AutoRenewalException("not released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AutoRenewalException("interrupted", e);
            }
        }
    }
}
