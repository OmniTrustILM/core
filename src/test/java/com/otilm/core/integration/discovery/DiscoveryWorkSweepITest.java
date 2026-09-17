package com.otilm.core.integration.discovery;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.listeners.discovery.DiscoveryRunReaper;
import com.otilm.core.messaging.jms.listeners.discovery.DiscoveryWorkClaimer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cluster-level behaviour of the discovery work sweep against the real PostgreSQL container: the advisory lock admits
 * one claimer at a time, a claimed row is atomically rescheduled so a window publishes it once, and the reaper honours
 * the work-lost grace window and the stopped-run expiry. Not {@code @Transactional}: the claimer and reaper commit
 * their own transactions, so seeded data must be committed too ({@code TestDatabaseCleaner} wipes it between tests).
 */
class DiscoveryWorkSweepITest extends BaseSpringBootTest {

    private static final long AWAIT_TIMEOUT_SECONDS = 15;

    @Autowired
    private DiscoveryWorkClaimer claimer;
    @Autowired
    private DiscoveryRunReaper reaper;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private ClusterOperationSynchronizer synchronizer;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DataSource testDataSource;

    private final ExecutorService lockHolderThread = Executors.newSingleThreadExecutor();

    @AfterEach
    void stopLockHolder() {
        lockHolderThread.shutdownNow();
    }

    // ------------------------------------------------------------------ claim

    @Test
    void dueRow_isClaimedOnceAndRescheduledIntoTheNextWindow() {
        UUID runUuid = v2Run(DiscoveryStatus.IN_PROGRESS).getUuid();
        workWriter.schedule(runUuid, DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).minusHours(1));
        OffsetDateTime beforeClaim = OffsetDateTime.now(ZoneOffset.UTC);

        List<DiscoveryWorkMessage> claimed = claimer.claimDueBatch(10, OffsetDateTime.now(ZoneOffset.UTC));

        assertThat(claimed).hasSize(1);
        assertThat(claimed.get(0).discoveryUuid()).isEqualTo(runUuid);
        assertThat(claimed.get(0).workType()).isEqualTo(DiscoveryWorkType.STATUS);
        assertThat(claimed.get(0).attempt()).isZero();
        // The reschedule committed with the claim: attempt advanced, due time pushed past the claim
        // instant — the same window can never publish this row twice.
        var row = workRepository.findAll().get(0);
        assertThat(row.getAttempt()).isEqualTo(1);
        assertThat(row.getNextDueAt()).isAfter(beforeClaim);
    }

    @Test
    void claim_skipsWhileAnotherNodeHoldsTheSweepLock() throws Exception {
        UUID runUuid = v2Run(DiscoveryStatus.IN_PROGRESS).getUuid();
        workWriter.schedule(runUuid, DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).minusHours(1));

        CountDownLatch release = new CountDownLatch(1);
        CompletableFuture<Boolean> acquired = new CompletableFuture<>();
        lockHolderThread.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
            acquired.complete(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP));
            try {
                release.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        }));
        assertThat(acquired.get(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();

        try {
            assertThat(claimer.claimDueBatch(10, OffsetDateTime.now(ZoneOffset.UTC)))
                    .as("contended claim must skip, not block")
                    .isEmpty();
            var row = workRepository.findAll().get(0);
            assertThat(row.getAttempt()).as("a skipped claim must not touch the row").isZero();
        } finally {
            release.countDown();
        }
        lockHolderThread.shutdown();
        assertThat(lockHolderThread.awaitTermination(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();

        assertThat(claimer.claimDueBatch(10, OffsetDateTime.now(ZoneOffset.UTC)))
                .as("released lock frees the window")
                .hasSize(1);
    }

    // ------------------------------------------------------------------ reaper: work lost

    @Test
    void reap_leavesAFreshWorkLessRunAlone() {
        UUID runUuid = v2Run(DiscoveryStatus.IN_PROGRESS).getUuid();

        reaper.reap();

        assertThat(discoveryRepository.findByUuid(runUuid).orElseThrow().getStatus())
                .as("the initiate window (younger than reap-grace) is not a loss")
                .isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void reap_failsAWorkLessRunPastTheGraceWindow() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        backdateCreated(run.getUuid(), OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10));

        reaper.reap();

        Discovery reaped = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(reaped.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reaped.getMessage()).contains("work lost");
        assertThat(reaped.getEndTime()).isNotNull();
        assertThat(reaped.getCheckpoint()).isNull();
    }

    @Test
    void reap_ignoresARunWhoseAgendaIsAlive() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        backdateCreated(run.getUuid(), OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10));
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(1));

        reaper.reap();

        assertThat(discoveryRepository.findByUuid(run.getUuid()).orElseThrow().getStatus())
                .isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void reap_ignoresV1Runs() {
        Discovery run = new Discovery();
        run.setName("legacy-scan");
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        UUID runUuid = discoveryRepository.saveAndFlush(run).getUuid();
        backdateCreated(runUuid, OffsetDateTime.now(ZoneOffset.UTC).minusHours(20));

        reaper.reap();

        assertThat(discoveryRepository.findByUuid(runUuid).orElseThrow().getStatus())
                .as("v1 runs have no agenda by design; their lifecycle is the v1 flow's")
                .isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    // ------------------------------------------------------------------ reaper: stop expiry

    @Test
    void reap_cancelsAStoppedRunPastItsResumeWindow() {
        Discovery run = v2Run(DiscoveryStatus.STOPPED);
        run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(8));
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("cursor", "abc"));
        discoveryRepository.saveAndFlush(run);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(1));

        reaper.reap();

        Discovery reaped = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(reaped.getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
        assertThat(reaped.getMessage()).contains("Stop expired");
        assertThat(reaped.getEndTime()).isNotNull();
        assertThat(reaped.getCheckpoint()).isNull();
        assertThat(workRepository.existsByDiscoveryUuid(run.getUuid()))
                .as("terminal transition drops the run's agenda rows")
                .isFalse();
    }

    @Test
    void reap_leavesAStoppedRunInsideItsResumeWindow() {
        Discovery run = v2Run(DiscoveryStatus.STOPPED);
        run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(1));
        discoveryRepository.saveAndFlush(run);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(1));

        reaper.reap();

        assertThat(discoveryRepository.findByUuid(run.getUuid()).orElseThrow().getStatus())
                .isEqualTo(DiscoveryStatus.STOPPED);
        assertThat(workRepository.existsByDiscoveryUuid(run.getUuid())).isTrue();
    }

    // ------------------------------------------------------------------ fixtures

    /**
     * A committed v2 run row (interface association present). The interface uuid resolves to no row on purpose: the
     * reaper's connector-side cancel is best-effort, and an unresolvable interface exercises exactly that path.
     */
    private Discovery v2Run(DiscoveryStatus status) {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        return discoveryRepository.saveAndFlush(run);
    }

    /** {@code i_cre} is database-audited and not writable through the entity, so age runs at the SQL level. */
    private void backdateCreated(UUID runUuid, OffsetDateTime created) {
        new JdbcTemplate(testDataSource)
                .update("UPDATE " + dbSchema + ".discovery SET i_cre = ? WHERE uuid = ?", created, runUuid);
    }
}
