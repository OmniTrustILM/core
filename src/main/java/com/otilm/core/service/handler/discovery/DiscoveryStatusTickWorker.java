package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.model.discovery.DiscoveryProgressSnapshot;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The {@code STATUS} tick: one authoritative {@code status} call, and the run state it justifies.
 *
 * <p>
 * <b>This is the only place a connector-reported state becomes Core state.</b> Pushed events merely ask for this tick;
 * what the connector answers here is what commits.
 *
 */
@Component
public class DiscoveryStatusTickWorker {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryStatusTickWorker.class);

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryV2Client client;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryRunTerminator terminator;
    private final DiscoveryTickBudget budget;
    private final DiscoveryWorkProperties workProperties;
    private final TransactionHandler transactionHandler;

    public DiscoveryStatusTickWorker(DiscoveryRepository discoveryRepository, DiscoveryV2Client client,
            DiscoveryWorkWriter workWriter, DiscoveryRunTerminator terminator, DiscoveryTickBudget budget,
            DiscoveryWorkProperties workProperties, TransactionHandler transactionHandler) {
        this.discoveryRepository = discoveryRepository;
        this.client = client;
        this.workWriter = workWriter;
        this.terminator = terminator;
        this.budget = budget;
        this.workProperties = workProperties;
        this.transactionHandler = transactionHandler;
    }

    public void tick(UUID discoveryUuid, int attempt) {
        Discovery run = discoveryRepository.findByUuid(discoveryUuid).orElse(null);
        if (run == null) {
            // The agenda cascaded away with the run; this is a redelivery of an obsolete tick.
            logger.debug("Dropping status tick for discovery {}: the run no longer exists", discoveryUuid);
            return;
        }
        if (DiscoveryRunLifecycle.hasLeftTheConnector(run.getStatus())) {
            // Terminal, or handed over to processing: either way the connector no longer owns this run and its
            // handle is gone, so calling status would read a 404 as "the run vanished" and end a healthy import.
            logger.debug("Dropping status tick for discovery {}: already {}", discoveryUuid, run.getStatus());
            workWriter.deleteForRun(discoveryUuid, DiscoveryWorkType.STATUS);
            return;
        }

        DiscoveryStatusResponseDto status;
        try {
            // Outside any transaction, by the platform's connector-call rule.
            status = client.status(run);
        } catch (ConnectorException | RuntimeException e) {
            // RuntimeException too: see DiscoveryWorkListener for why an escape costs no budget.
            handleUnanswered(discoveryUuid, attempt, e);
            return;
        } catch (NotFoundException | AttributeException e) {
            // The call could not be assembled at all: the connector row or the run's attributes are gone.
            // Retrying cannot repair that, and the run has no way to make progress.
            terminator
                    .endConnectorOwned(discoveryUuid, DiscoveryStatus.FAILED,
                            "The discovery run can no longer be addressed at its connector");
            return;
        }

        if (status.getState() == null) {
            // Required on the wire, so its absence is not an answer: unguarded, the null would reach
            // state.getCode() inside the transaction and escape to the listener's log-and-acknowledge instead of
            // spending the budget.
            handleNonConformant(discoveryUuid, attempt);
            return;
        }

        if (apply(discoveryUuid, status, run.getStatus())) {
            // A clear answer refreshes the budget without restarting the backoff ramp: the counter drops to
            // the rung where the ladder already reached its slowest delay.
            workWriter
                    .resetAttempt(discoveryUuid, DiscoveryWorkType.STATUS,
                            workProperties.scheduleFor(DiscoveryWorkType.STATUS).ceilingAttempt());
        }
    }

    /**
     * A tick the connector did not answer. Below the budget the run keeps its agenda row, which the sweep's claimer
     * pushes up the backoff ladder when it takes it next.
     */
    private void handleUnanswered(UUID discoveryUuid, int attempt, Throwable e) {
        if (!budget
                .spendOnUnanswered(discoveryUuid, DiscoveryWorkType.STATUS, attempt, e,
                        "The connector stopped answering status polls for this run")) {
            logger
                    .warn("Status poll {} for discovery {} failed, retrying when next due: {}", attempt, discoveryUuid,
                            e.getMessage());
        }
    }

    /**
     * A status answer Core cannot act on. Counted against the budget like any other unanswered tick, so a connector
     * that keeps omitting the run state ends the run rather than stalling it forever.
     */
    private void handleNonConformant(UUID discoveryUuid, int attempt) {
        if (!budget
                .spend(discoveryUuid, DiscoveryWorkType.STATUS, attempt,
                        "The connector's status answers omitted the run state")) {
            logger
                    .warn("Status poll {} for discovery {} returned no run state; retrying when next due", attempt,
                            discoveryUuid);
        }
    }

    /**
     * Commits what the connector reported.
     *
     * @return whether the run is still live and its budget should be refreshed — false once the answer was itself
     * terminal, where there is no longer an agenda row to refresh
     */
    private boolean apply(UUID discoveryUuid, DiscoveryStatusResponseDto status, DiscoveryStatus polledAs) {
        DiscoveryRunState state = status.getState();
        return Boolean.TRUE.equals(transactionHandler.runInNewTransaction(() -> {
            Discovery locked = discoveryRepository.findWithLockByUuid(discoveryUuid).orElse(null);
            // Re-assert under the row lock: another tick may have ended the run, or the drain may have handed it
            // over to processing, while this status call was in flight. Terminal answers come through here too --
            // routed around this check they would end a run the drain had already handed over safely.
            if (locked == null || DiscoveryRunLifecycle.hasLeftTheConnector(locked.getStatus())) {
                return false;
            }
            // A stop or a resume can land while the poll is in flight, and neither leaves the connector, so the
            // check above lets it through. What came back describes the run before that transition, so applying it
            // would undo the newer one -- a stop answered by an in-flight RUNNING would restart the run and clear
            // the resume window the reaper bounds. The agenda row survives, so the next tick polls the run as it is.
            if (locked.getStatus() != polledAs) {
                logger
                        .debug("Dropping status tick for discovery {}: it moved from {} to {} during the poll",
                                discoveryUuid, polledAs, locked.getStatus());
                return false;
            }
            // What the connector reported is recorded whatever it was, including on the endings: connector_state
            // and connector_status are its view of the run, and losing them on the one answer that matters most
            // leaves the operator without the reason.
            String previousConnectorState = locked.getConnectorState();
            locked.setConnectorState(state.getCode());
            locked.setConnectorStatus(connectorStatusFor(state));
            if (DiscoveryProgressSnapshot.reportsSomething(status.getProgress())) {
                locked.setProgress(status.getProgress());
            }
            if (state == DiscoveryRunState.FAILED || state == DiscoveryRunState.CANCELLED) {
                terminator
                        .applyTerminalState(locked, terminalStatusFor(state),
                                "The connector reported the run as " + state.getLabel());
                workWriter.deleteForRun(discoveryUuid);
                return false;
            }
            applyLiveState(locked, state, previousConnectorState);
            return true;
        }));
    }

    private void applyLiveState(Discovery run, DiscoveryRunState state, String previousConnectorState) {
        switch (state) {
            case RUNNING -> {
                // Only an explicit resume moves a stopped run. A connector that keeps answering RUNNING after
                // acknowledging a stop is a divergence, recorded in connector_status above and visible there,
                // rather than grounds to restart a run the user paused.
                if (run.getStatus() != DiscoveryStatus.STOPPED) {
                    run.setStatus(DiscoveryStatus.IN_PROGRESS);
                    clearResumeWindow(run);
                }
            }
            case STOPPED -> {
                run.setStatus(DiscoveryStatus.STOPPED);
                // Starts the resume window the reaper bounds. Stamped only when the run is not already
                // inside one, so repeated STOPPED answers cannot keep pushing the deadline out.
                if (run.getStoppedAt() == null) {
                    run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
                }
            }
            // Core stays IN_PROGRESS through the tail drain and flips to PROCESSING only once the drain has
            // fully caught up -- entering PROCESSING with items still at the connector would strand them.
            case COMPLETED -> {
                run.setStatus(DiscoveryStatus.IN_PROGRESS);
                clearResumeWindow(run);
                // Only on the transition. Scheduling re-arms a row from scratch, counter included, so doing it
                // on every repeated COMPLETED answer would reset the drain's budget faster than the drain can
                // spend it and a permanently failing drain would never end the run.
                if (!DiscoveryRunState.COMPLETED.getCode().equals(previousConnectorState)) {
                    workWriter.schedule(run.getUuid(), DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC));
                }
            }
            default -> throw new IllegalStateException("Unhandled live discovery run state " + state);
        }
    }

    /**
     * A run that is no longer stopped carries no resume deadline. Leaving the old timestamp behind would let a much
     * later stop inherit an already-expired window and be auto-cancelled the moment it pauses.
     */
    private static void clearResumeWindow(Discovery run) {
        run.setStoppedAt(null);
    }

    private static DiscoveryStatus connectorStatusFor(DiscoveryRunState state) {
        return switch (state) {
            case RUNNING -> DiscoveryStatus.IN_PROGRESS;
            case STOPPED -> DiscoveryStatus.STOPPED;
            case COMPLETED -> DiscoveryStatus.COMPLETED;
            case FAILED -> DiscoveryStatus.FAILED;
            case CANCELLED -> DiscoveryStatus.CANCELLED;
        };
    }

    private static DiscoveryStatus terminalStatusFor(DiscoveryRunState state) {
        return state == DiscoveryRunState.CANCELLED ? DiscoveryStatus.CANCELLED : DiscoveryStatus.FAILED;
    }
}
