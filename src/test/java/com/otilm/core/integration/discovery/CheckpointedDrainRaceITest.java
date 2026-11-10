package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.CheckpointComparison;
import com.otilm.core.service.handler.discovery.DiscoveryEventIngestor;
import com.otilm.core.service.handler.discovery.DrainPageOutcome;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.seeders.DiscoveryRunSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Two duplicate drain ticks of one checkpointed run, built from the same revision, applying their pages at the same
 * time. The run's row lock serializes them and the revision decides: exactly one page lands. Not transactional, so each
 * tick commits on its own connection as it does in production.
 */
class CheckpointedDrainRaceITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryEventIngestor ingestor;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryRunSeeder runSeeder;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void appliesExactlyOnePage_whenTwoDuplicateDrainsRaceForTheRun() throws Exception {
        // given
        Discovery run = checkpointedRun();
        long revisionBothTicksRead = run.getCheckpointRevision();
        DiscoveryResultsResponseDto firstPage = page(position("cursor-2"), keyItem(1, "key-a"), keyItem(2, "key-b"));
        DiscoveryResultsResponseDto secondPage = page(position("cursor-3"), keyItem(1, "key-a"), keyItem(2, "key-b"),
                keyItem(3, "key-c"));
        ExecutorService ticks = Executors.newFixedThreadPool(2);

        // when
        List<Future<DrainPageOutcome>> applied;
        try {
            applied = whileHoldingTheRunsLock(run, () -> {
                Future<DrainPageOutcome> first = ticks
                        .submit(() -> ingestor
                                .applyDrainPage(run.getUuid(), firstPage, revisionBothTicksRead,
                                        run.getDeliveryMode()));
                Future<DrainPageOutcome> second = ticks
                        .submit(() -> ingestor
                                .applyDrainPage(run.getUuid(), secondPage, revisionBothTicksRead,
                                        run.getDeliveryMode()));
                awaitTicksWaitingForALock(2);
                return List.of(first, second);
            });
        } finally {
            ticks.shutdown();
        }
        DrainPageOutcome firstOutcome = applied.get(0).get(30, TimeUnit.SECONDS);
        DrainPageOutcome secondOutcome = applied.get(1).get(30, TimeUnit.SECONDS);

        // then
        assertThat(List.of(firstOutcome, secondOutcome))
                .containsExactlyInAnyOrder(DrainPageOutcome.ADVANCED, DrainPageOutcome.STALE);
        DiscoveryResultsResponseDto winner = firstOutcome == DrainPageOutcome.ADVANCED ? firstPage : secondPage;
        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getCheckpointRevision()).isEqualTo(revisionBothTicksRead + 1);
        assertThat(CheckpointComparison.same(persisted.getCheckpoint(), winner.getCheckpoint())).isTrue();
        assertThat(stagedRefs(run))
                .containsExactlyInAnyOrderElementsOf(
                        winner.getItems().stream().map(DiscoveredItemDto::getUniqueRef).toList());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Holds the run's row lock in a transaction of its own while {@code body} starts the ticks, then lets them go. */
    private <T> T whileHoldingTheRunsLock(Discovery run, Supplier<T> body) {
        return new TransactionTemplate(transactionManager).execute(status -> {
            entityManager
                    .createNativeQuery("SELECT uuid FROM discovery WHERE uuid = :uuid FOR UPDATE")
                    .setParameter("uuid", run.getUuid())
                    .getResultList();
            return body.get();
        });
    }

    /**
     * Waits until {@code count} sessions are blocked on a lock, so both ticks have read before either writes. The
     * activity view is a snapshot taken once per transaction, so each look clears it first.
     */
    private void awaitTicksWaitingForALock(int count) {
        await()
                .atMost(Duration.ofSeconds(20))
                .pollInterval(Duration.ofMillis(50))
                .pollInSameThread()
                .alias("both ticks waiting for the run's lock")
                .until(() -> sessionsWaitingForALock() >= count);
    }

    private int sessionsWaitingForALock() {
        entityManager.createNativeQuery("SELECT pg_stat_clear_snapshot()").getSingleResult();
        Number waiting = (Number) entityManager
                .createNativeQuery("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        + "AND wait_event_type = 'Lock'")
                .getSingleResult();
        return waiting.intValue();
    }

    private static DiscoveryResultsResponseDto page(List<MetadataAttribute> checkpoint, DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence((long) items.length);
        page.setMore(true);
        page.setCheckpoint(checkpoint);
        return page;
    }

    private static List<MetadataAttribute> position(String value) {
        return DiscoveryCheckpointFixture.checkpoint("position", value);
    }

    private static DiscoveredItemDto keyItem(long sequence, String uniqueRef) {
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(aPublicKey().withFingerprint("fingerprint-" + uniqueRef).build());
        return item;
    }

    private List<String> stagedRefs(Discovery run) {
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> item.getDiscoveryUuid().equals(run.getUuid()))
                .map(DiscoveryItem::getUniqueRef)
                .toList();
    }

    private Discovery checkpointedRun() {
        Discovery run = runSeeder.seedV2Run(DiscoveryStatus.IN_PROGRESS);
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        run.setCheckpointRevision(3);
        run.setCheckpoint(position("cursor-0"));
        return discoveryRepository.saveAndFlush(run);
    }
}
