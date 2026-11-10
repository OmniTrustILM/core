package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkLease;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The {@code DRAIN} tick: one bounded page of results, ingested, then a decision about what comes next.
 *
 * <p>
 * <b>Only a fully acknowledged run hands over.</b> A connector reporting {@code completed} and a page reporting
 * {@code more: false} still leave the cursor free to sit below the run-wide {@code highestSequence} — items produced
 * but not handed over — so the swap to {@code PROCESSING} waits for the cursor to catch up.
 */
@Component
public class DiscoveryDrainTickWorker {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryDrainTickWorker.class);

    static final int MIN_PAGE_ITEMS = 100;
    static final long MIN_PAGE_BYTES = 1_048_576L;

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryV2Client client;
    private final DiscoveryEventIngestor ingestor;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryWorkProducer workProducer;
    private final DiscoveryRunTerminator terminator;
    private final DiscoveryTickBudget budget;
    private final DiscoveryWorkProperties workProperties;
    private final TransactionHandler transactionHandler;
    private final DiscoveryWorkLease lease;
    private final int maxItems;
    private final long maxBytes;

    public DiscoveryDrainTickWorker(DiscoveryRepository discoveryRepository, DiscoveryV2Client client,
            DiscoveryEventIngestor ingestor, DiscoveryWorkWriter workWriter, DiscoveryWorkProducer workProducer,
            DiscoveryRunTerminator terminator, DiscoveryTickBudget budget, DiscoveryWorkProperties workProperties,
            TransactionHandler transactionHandler, DiscoveryWorkLease lease,
            @Value("${discovery.drain.max-items:500}") int maxItems,
            @Value("${discovery.drain.max-bytes:5242880}") long maxBytes) {
        this.lease = lease;
        this.discoveryRepository = discoveryRepository;
        this.client = client;
        this.ingestor = ingestor;
        this.workWriter = workWriter;
        this.workProducer = workProducer;
        this.terminator = terminator;
        this.budget = budget;
        this.workProperties = workProperties;
        this.transactionHandler = transactionHandler;
        // Fail at startup rather than on every drain. A checkpointed connector never splits one target's items
        // across pages, so a page smaller than one target stalls the run, and a non-positive bound produces a
        // request the connector rejects each time it is sent.
        if (maxItems < MIN_PAGE_ITEMS) {
            throw new IllegalArgumentException("discovery.drain.max-items must be at least " + MIN_PAGE_ITEMS);
        }
        if (maxBytes < MIN_PAGE_BYTES) {
            throw new IllegalArgumentException("discovery.drain.max-bytes must be at least " + MIN_PAGE_BYTES);
        }
        this.maxItems = maxItems;
        this.maxBytes = maxBytes;
    }

    public void tick(DiscoveryWorkTick tick) {
        UUID discoveryUuid = tick.discoveryUuid();
        int attempt = tick.attempt();
        Discovery run = discoveryRepository.findByUuid(discoveryUuid).orElse(null);
        if (run == null) {
            logger.debug("Dropping drain tick for discovery {}: the run no longer exists", discoveryUuid);
            return;
        }
        if (DiscoveryRunLifecycle.hasLeftTheConnector(run.getStatus())) {
            // Nothing is left at the connector once the run has finished or handed over. Only this tick's own row
            // goes: a PROCESSING run still needs its PROCESS row, and taking the whole agenda would strand the
            // import and leave the reaper reading a live run as work-lost.
            logger.debug("Dropping drain tick for discovery {}: already {}", discoveryUuid, run.getStatus());
            workWriter.deleteForRun(discoveryUuid, DiscoveryWorkType.DRAIN);
            return;
        }

        DiscoveryResultsResponseDto page;
        try {
            // Outside any transaction, by the platform's connector-call rule.
            page = client.results(run, maxItems, maxBytes);
        } catch (ConnectorException | RuntimeException e) {
            // RuntimeException too: one that escapes to the listener moves the row up a rung but can never end the run.
            handleUnanswered(discoveryUuid, attempt, e);
            return;
        } catch (NotFoundException | AttributeException e) {
            terminator
                    .endConnectorOwned(discoveryUuid, DiscoveryStatus.FAILED,
                            "The discovery run can no longer be addressed at its connector");
            return;
        }

        if (page.getItems() == null || page.getMore() == null || page.getHighestSequence() == null) {
            // All three are required on the wire precisely so their absence cannot be read as an answer. A
            // page that means "no items" sends an empty array; a missing "items" or a missing "more" read as
            // an answer hands a half-drained run to processing and releases the connector handle, which is
            // permanent, silent loss. Spend the budget on it instead.
            handleNonConformant(discoveryUuid, attempt);
            return;
        }

        // The connector call may have taken most of the lease; staging must not run past it.
        if (!tick.renew()) {
            logger.debug("Dropping a drained page for discovery {}: another tick holds its row now", discoveryUuid);
            return;
        }
        boolean advanced;
        try {
            advanced = ingestor.applyDrainPage(discoveryUuid, page);
        } catch (RuntimeException e) {
            // Staging sits outside the connector-call catch, so without this a deterministic page failure -- a
            // payload that will not serialize, a constraint violation -- escapes to the listener's
            // log-and-acknowledge and the same poison page retries forever, never reaching the budget. The page's
            // transaction has already rolled back, so the cursor is untouched either way.
            handleUnstageable(discoveryUuid, attempt, e);
            return;
        }
        continueAfter(tick, run, page, advanced);
    }

    /**
     * A page Core cannot act on. Counted against the drain budget like any other unanswered tick, so a connector that
     * keeps omitting required fields ends the run rather than stalling it forever.
     */
    private void handleNonConformant(UUID discoveryUuid, int attempt) {
        if (!budget
                .spend(discoveryUuid, DiscoveryWorkType.DRAIN, attempt,
                        "The connector's results omitted a field the contract requires")) {
            logger
                    .warn("Drain {} for discovery {} returned a page missing items, more or highestSequence; retrying "
                            + "when next due", attempt, discoveryUuid);
        }
    }

    /**
     * A page the connector delivered and Core could not stage. Charged to the same budget — a page that will never
     * stage must not retry forever — but ended with Core named as the party that failed, because on this path the
     * connector answered and answered correctly.
     */
    private void handleUnstageable(UUID discoveryUuid, int attempt, RuntimeException e) {
        logger.error("Ingesting a drained page for discovery {} failed: {}", discoveryUuid, e.getMessage(), e);
        budget
                .spend(discoveryUuid, DiscoveryWorkType.DRAIN, attempt,
                        "Core could not store the discovered items this run's connector handed over");
    }

    /**
     * Decides the run's next drain step from what the page said, and — where the answer is "there is more, now" —
     * publishes that step rather than waiting for a sweep to notice.
     */
    private void continueAfter(DiscoveryWorkTick tick, Discovery run, DiscoveryResultsResponseDto page,
            boolean advanced) {
        UUID discoveryUuid = tick.discoveryUuid();
        if (Boolean.TRUE.equals(page.getMore())) {
            if (advanced) {
                drainAgain(tick, "the connector reports more items");
            } else {
                // "More to come" that carried nothing new is a connector repeating itself. Publishing again
                // would spin as fast as it answers, so this climbs the ladder and eventually ends the run.
                awaitTheRest(tick, page.getHighestSequence());
            }
            return;
        }
        if (!DiscoveryRunState.COMPLETED.getCode().equals(run.getConnectorState())) {
            // The connector is still producing and has nothing ready this moment.
            budget.refreshAtSlowestRung(tick);
            return;
        }
        // The swap is the only catch-up check there is, and deliberately so: it re-asserts the cursor against
        // highestSequence under the run row's lock, which a separate pre-check could only do without one.
        Optional<Handover> handover = swapToProcessing(discoveryUuid, page.getHighestSequence());
        if (handover.isEmpty()) {
            awaitTheRest(tick, page.getHighestSequence());
            return;
        }
        // Strictly after the handover commits. The acknowledgement lets the connector discard the run's whole
        // state, so sending it before a swap that might roll back would licence throwing away a run Core never
        // finished taking over. The handle is replayed onto the detached entity purely to make this one call.
        run.setCheckpoint(handover.get().releasedHandle());
        sendFullAck(run, page.getHighestSequence());
        workProducer.produceMessage(handover.get().processTick());
    }

    /**
     * The contract's full acknowledgement: a drain at {@code afterSequence == highestSequence}, which tells the
     * connector every item was received and it may discard the run's state. Best-effort by design — the connector
     * retains that state for 24 hours regardless, so a failure here costs retention, not data.
     *
     * <p>
     * Sent after the handover commits, against the handle it released. The contract frames the ack as following the
     * run's terminal state, which Core reaches later, in processing — so this is the earliest point at which the
     * handover is durable and the latest at which the handle still exists.
     */
    private void sendFullAck(Discovery run, Long highestSequence) {
        try {
            client.acknowledge(run, highestSequence);
        } catch (ConnectorException | NotFoundException | AttributeException | RuntimeException e) {
            logger
                    .warn("Full-ack drain failed for discovery {}; the connector keeps the run's state until its own "
                            + "retention expires", run.getUuid(), e);
        }
    }

    /**
     * The connector reported itself complete but counted more items than it handed over. Climbing the ladder rather
     * than draining again at once matters here: this is the one branch that can repeat without making progress, and a
     * due-now retry would be an unbounded stream of {@code results} calls against a connector that may never catch up.
     * Spending the budget ends the run with a reason instead.
     */
    private void awaitTheRest(DiscoveryWorkTick tick, Long highestSequence) {
        int next = tick.attempt() + 1;
        if (next >= workProperties.scheduleFor(DiscoveryWorkType.DRAIN).maxAttempts()) {
            terminator
                    .endConnectorOwned(tick.discoveryUuid(), DiscoveryStatus.FAILED,
                            "The connector reported %d item(s) but never handed them all over"
                                    .formatted(highestSequence));
            return;
        }
        tick
                .reschedule(next,
                        OffsetDateTime
                                .now(ZoneOffset.UTC)
                                .plus(workProperties.scheduleFor(DiscoveryWorkType.DRAIN).delayFor(next)));
    }

    /**
     * Commits the handover to Core-side processing, but only once every item the connector counted has been ingested.
     *
     * @return empty when no handover happened — the cursor is still behind, or another tick got there first; otherwise
     * a {@link Handover} carrying the released connector handle, which may itself be absent since the contract marks a
     * run's {@code checkpoint} optional, and the processing tick to publish
     */
    private Optional<Handover> swapToProcessing(UUID discoveryUuid, Long highestSequence) {
        return transactionHandler.runInNewTransaction(() -> {
            Discovery locked = discoveryRepository.findWithLockByUuid(discoveryUuid).orElse(null);
            // The snapshot this decision started from predates the connector call. Re-assert both halves of the
            // precondition: a concurrent STATUS tick may have paused the run, and another drain may already have
            // handed it over — swapping again would publish a second PROCESS tick against the same run.
            if (locked == null || locked.getStatus() != DiscoveryStatus.IN_PROGRESS
                    || !DiscoveryRunState.COMPLETED.getCode().equals(locked.getConnectorState())) {
                return Optional.empty();
            }
            long acknowledged = locked.getLastAppliedSequence();
            if (highestSequence != null && acknowledged < highestSequence) {
                logger
                        .info("Discovery {} drained to {} of {} items; staying in the drain", discoveryUuid,
                                acknowledged, highestSequence);
                return Optional.empty();
            }
            List<MetadataAttribute> handle = locked.getCheckpoint();
            locked.setStatus(DiscoveryStatus.PROCESSING);
            // The connector owns nothing from here on, so its run handle is released with the same write
            // that hands the run to processing.
            locked.setCheckpoint(null);
            // Delete then schedule inside one transaction: a live run's agenda must never be observably
            // empty, or the reaper would read it as lost work.
            workWriter.deleteForRun(discoveryUuid);
            // Leased to the tick published once this commits.
            DiscoveryWorkMessage processTick = lease.scheduleLeased(discoveryUuid, DiscoveryWorkType.PROCESS);
            logger.info("Discovery {} drained {} items in full; processing them now", discoveryUuid, acknowledged);
            return Optional.of(new Handover(handle, processTick));
        });
    }

    /**
     * Hands the row to the next page's tick with the attempt counter this page earned back, and publishes that tick
     * directly.
     */
    private void drainAgain(DiscoveryWorkTick tick, String why) {
        logger.debug("Draining discovery {} again immediately: {}", tick.discoveryUuid(), why);
        tick.handOver().ifPresent(workProducer::produceMessage);
    }

    /**
     * A tick the connector did not answer. Below the budget, the listener's retry moves the row one rung up its backoff
     * ladder.
     */
    private void handleUnanswered(UUID discoveryUuid, int attempt, Throwable e) {
        if (!budget
                .spendOnUnanswered(discoveryUuid, DiscoveryWorkType.DRAIN, attempt, e,
                        "The connector stopped handing over discovered items for this run")) {
            logger
                    .warn("Drain {} for discovery {} failed, retrying when next due: {}", attempt, discoveryUuid,
                            e.getMessage());
        }
    }

    /**
     * A handover that happened, carrying the connector handle it released.
     *
     * <p>
     * A type rather than a nullable handle, because the handle itself is legitimately absent: the contract marks a
     * run's {@code checkpoint} optional, so "no handle" and "no handover" are different answers that a bare null
     * conflated — and reading a handle-less handover as "no swap" skipped both the {@code PROCESS} publication and the
     * full acknowledgement for a run that had in fact handed over.
     */
    private record Handover(List<MetadataAttribute> releasedHandle, DiscoveryWorkMessage processTick) {
    }
}
