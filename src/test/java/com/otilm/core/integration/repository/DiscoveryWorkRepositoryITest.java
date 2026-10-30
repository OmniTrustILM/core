package com.otilm.core.integration.repository;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SQL-level coverage for the discovery work agenda. The {@code ON CONFLICT} upsert is idempotent per run and work type.
 * The due query orders soonest-first and excludes the not-yet-due. Deleting a run cascades its agenda rows away at the
 * database level — the sweep must never meet work for a run that no longer exists.
 */
@Transactional
class DiscoveryWorkRepositoryITest extends BaseSpringBootTest {

    // Truncated to what timestamptz can hold, so a stored value reads back equal to what was written.
    private static final OffsetDateTime NOW = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);

    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void doubleScheduleKeepsOneRowAndMovesTheDueTime() {
        UUID runUuid = aRun();

        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW.plusMinutes(1));
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW.plusMinutes(5));

        List<DiscoveryWork> rows = workRepository.findAll();
        assertThat(rows).hasSize(1);
        // Compared as instants: the driver may hand the timestamptz back under a different zone offset.
        assertThat(rows.get(0).getNextDueAt().toInstant()).isEqualTo(NOW.plusMinutes(5).toInstant());
        assertThat(rows.get(0).getAttempt()).isZero();
    }

    @Test
    void dueQueryOrdersSoonestFirstAndExcludesTheNotYetDue() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.PROCESS.name(), NOW.plusHours(2));
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW.minusMinutes(1));
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW.minusMinutes(10));

        List<DiscoveryWork> due = workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(NOW, PageRequest.of(0, 10));

        assertThat(due)
                .extracting(DiscoveryWork::getWorkType)
                .containsExactly(DiscoveryWorkType.STATUS, DiscoveryWorkType.DRAIN);
    }

    @Test
    void rescheduleByRunAndTypeMovesAttemptAndDueTime() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);

        workRepository.reschedule(runUuid, DiscoveryWorkType.DRAIN, 3, NOW.plusMinutes(30));
        entityManager.clear();

        DiscoveryWork row = workRepository.findAll().get(0);
        assertThat(row.getAttempt()).isEqualTo(3);
        assertThat(row.getNextDueAt().toInstant()).isEqualTo(NOW.plusMinutes(30).toInstant());
    }

    @Test
    void reArmingABackedOffRowResetsItsAttemptCounter() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);
        workRepository.reschedule(runUuid, DiscoveryWorkType.DRAIN, 7, NOW.plusHours(1));

        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);
        entityManager.clear();

        DiscoveryWork row = workRepository.findAll().get(0);
        assertThat(row.getAttempt())
                .as("scheduling is a fresh start; in-flight backoff is reschedule()'s job")
                .isZero();
        assertThat(row.getNextDueAt().toInstant()).isEqualTo(NOW.toInstant());
    }

    @Test
    void resetAttemptToLowersOnlyACounterAboveTheFloor() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW);
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);
        workRepository.reschedule(runUuid, DiscoveryWorkType.STATUS, 50, NOW.plusHours(1));
        workRepository.reschedule(runUuid, DiscoveryWorkType.DRAIN, 3, NOW.plusHours(1));

        workRepository.resetAttemptTo(runUuid, DiscoveryWorkType.STATUS, 6);
        workRepository.resetAttemptTo(runUuid, DiscoveryWorkType.DRAIN, 6);
        entityManager.clear();

        Map<DiscoveryWorkType, Integer> attempts = workRepository
                .findAll()
                .stream()
                .collect(Collectors.toMap(DiscoveryWork::getWorkType, DiscoveryWork::getAttempt));
        assertThat(attempts)
                .containsEntry(DiscoveryWorkType.STATUS, 6)
                .as("a still-ramping row stays untouched; the guard lives in the query")
                .containsEntry(DiscoveryWorkType.DRAIN, 3);
    }

    @Test
    void expeditingABackedOffRowMovesItWithoutRefundingItsBudget() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW);
        workRepository.reschedule(runUuid, DiscoveryWorkType.STATUS, 40, NOW.plusHours(1));

        workRepository.expedite(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW);
        entityManager.clear();

        DiscoveryWork row = workRepository.findAll().get(0);
        assertThat(row.getNextDueAt().toInstant()).isEqualTo(NOW.toInstant());
        assertThat(row.getAttempt())
                .as("a push saying 'look now' is not an answer from the connector, so it buys no budget back")
                .isEqualTo(40);
    }

    @Test
    void expeditingARunWithNoRowCreatesOneAtTheStartOfItsBudget() {
        UUID runUuid = aRun();

        workRepository.expedite(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);

        DiscoveryWork row = workRepository.findAll().get(0);
        assertThat(row.getWorkType()).isEqualTo(DiscoveryWorkType.DRAIN);
        assertThat(row.getAttempt()).isZero();
    }

    @Test
    void existsByDiscoveryUuidSeesOnlyTheRunsOwnRows() {
        UUID runWithWork = aRun();
        UUID runWithout = aRun();
        workRepository.schedule(UUID.randomUUID(), runWithWork, DiscoveryWorkType.STATUS.name(), NOW);

        assertThat(workRepository.existsByDiscoveryUuid(runWithWork)).isTrue();
        assertThat(workRepository.existsByDiscoveryUuid(runWithout)).isFalse();
    }

    @Test
    void deleteByDiscoveryUuidRemovesOnlyTheTargetedRunsRows() {
        UUID runA = aRun();
        UUID runB = aRun();
        workRepository.schedule(UUID.randomUUID(), runA, DiscoveryWorkType.STATUS.name(), NOW);
        workRepository.schedule(UUID.randomUUID(), runB, DiscoveryWorkType.STATUS.name(), NOW);

        workRepository.deleteByDiscoveryUuid(runA);
        entityManager.clear();

        List<DiscoveryWork> remaining = workRepository.findAll();
        assertThat(remaining).hasSize(1);
        assertThat(remaining.get(0).getDiscoveryUuid()).isEqualTo(runB);
    }

    @Test
    void deletingTheRunCascadesItsAgendaRows() {
        UUID runUuid = aRun();
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.STATUS.name(), NOW);
        workRepository.schedule(UUID.randomUUID(), runUuid, DiscoveryWorkType.DRAIN.name(), NOW);
        assertThat(workRepository.count()).isEqualTo(2);

        discoveryRepository.deleteById(runUuid);
        discoveryRepository.flush();

        assertThat(workRepository.count()).isZero();
    }

    /** A saved, flushed run row — flushed because the native upsert's foreign key reads the table, not the cache. */
    private UUID aRun() {
        Discovery run = new Discovery();
        run.setName("nightly-scan");
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        return discoveryRepository.saveAndFlush(run).getUuid();
    }
}
