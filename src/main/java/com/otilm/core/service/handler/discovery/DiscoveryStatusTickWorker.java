package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResourceProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryProgressSnapshot;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
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
    private final AttributeEngine attributeEngine;
    private final DiscoveryMessageWriter messageWriter;
    private final Duration stoppedPollInterval;

    public DiscoveryStatusTickWorker(DiscoveryRepository discoveryRepository, DiscoveryV2Client client,
            DiscoveryWorkWriter workWriter, DiscoveryRunTerminator terminator, DiscoveryTickBudget budget,
            DiscoveryWorkProperties workProperties, TransactionHandler transactionHandler,
            AttributeEngine attributeEngine, DiscoveryMessageWriter messageWriter,
            @Value("${discovery.work.stopped-poll-interval:PT5M}") Duration stoppedPollInterval) {
        this.attributeEngine = attributeEngine;
        this.messageWriter = messageWriter;
        this.stoppedPollInterval = stoppedPollInterval;
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
            // Two status calls for one run can be in flight at once: a call slower than the claim floor is published
            // again. The connector's highest sequence never decreases, so an answer carrying less than what is already
            // recorded was taken earlier -- applying it would put older counters back, stamped as freshly recorded.
            if (arrivedOutOfOrder(locked, status)) {
                logger
                        .debug("Dropping status tick for discovery {}: it was taken at sequence {}, behind the {}"
                                + " already recorded", discoveryUuid, status.getHighestSequence(),
                                locked.getConnectorHighestSequence());
                return false;
            }
            if (status.getHighestSequence() != null) {
                locked.setConnectorHighestSequence(status.getHighestSequence());
            }
            // What the connector reported is recorded whatever it was, including on the endings: connector_state
            // and connector_status are its view of the run, and losing them on the one answer that matters most
            // leaves the operator without the reason.
            String previousConnectorState = locked.getConnectorState();
            locked.setConnectorState(state.getCode());
            locked.setConnectorStatus(connectorStatusFor(state));
            if (DiscoveryProgressSnapshot.reportsSomething(status.getProgress())) {
                locked.setProgress(DiscoveryProgressSnapshot.recorded(status.getProgress()));
                // Mirrored on every answer: this is the connector's own certificate figure and the listing carries no
                // other, so a running discovery would otherwise show none.
                connectorCertificateYield(locked).ifPresent(locked::setConnectorTotalCertificatesDiscovered);
            }
            applyRunMetadata(locked, status.getMeta());
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

    /**
     * The connector's metadata statement about the run: absent keeps what the run holds, a present list replaces it
     * whole, an empty list clears it. It lives in the attribute engine as the run's connector-sourced metadata, the
     * store the detail reads for a v1 run too, and is rewritten on every answer that carries one. Over the cap the
     * statement is dropped with a run message; unlike the checkpoint it is advisory, so the run goes on.
     */
    private void applyRunMetadata(Discovery locked, List<MetadataAttribute> meta) {
        if (meta == null) {
            return;
        }
        int size = DiscoveryProviderV2Adapter.serializedSize(meta);
        if (size > DiscoveryProviderV2Adapter.MAX_META_BYTES) {
            logger
                    .warn("Discovery {} sent {} bytes of run metadata, over the {} byte cap; dropped", locked.getUuid(),
                            size, DiscoveryProviderV2Adapter.MAX_META_BYTES);
            notRecorded(locked, "The connector's metadata about the run exceeded the size cap and was not recorded.");
            return;
        }
        // Checked before anything is deleted, so a malformed statement cannot take the previous one with it.
        if (!meta.stream().allMatch(DiscoveryStatusTickWorker::isRecordable)) {
            logger.warn("Discovery {} sent run metadata missing identity or properties; dropped", locked.getUuid());
            notRecorded(locked, "The connector's metadata about the run was malformed and was not recorded.");
            return;
        }
        ObjectAttributeContentInfo target = ObjectAttributeContentInfo
                .builder(Resource.DISCOVERY, locked.getUuid())
                .connector(locked.getConnectorUuid())
                .build();
        try {
            // A transaction of its own: the statement held so far is deleted before the new one is written, so one
            // the engine refuses part-way takes that deletion back with it and the run keeps what it held. The
            // message about it is filed in the answer's transaction, which goes on.
            transactionHandler.runInNewTransaction(() -> {
                try {
                    attributeEngine.deleteObjectAttributesContent(AttributeType.META, target);
                    attributeEngine.updateMetadataAttributes(meta, target);
                } catch (AttributeException e) {
                    throw new MetadataRefused(e);
                }
            });
        } catch (MetadataRefused refused) {
            logger
                    .warn("Discovery {}: run metadata could not be recorded: {}", locked.getUuid(),
                            refused.getCause().getMessage());
            notRecorded(locked, "The connector's metadata about the run was refused and was not recorded.");
        }
    }

    /** Carries the engine's checked refusal out of the replacement's transaction, rolling it back on the way. */
    private static final class MetadataRefused extends RuntimeException {
        private MetadataRefused(AttributeException cause) {
            super(cause);
        }
    }

    private void notRecorded(Discovery locked, String message) {
        messageWriter
                .append(locked.getUuid(), DiscoveryMessageSeverity.WARNING,
                        DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED, message);
    }

    /** What the attribute engine needs to register a definition and its content. */
    private static boolean isRecordable(MetadataAttribute attribute) {
        return attribute != null && attribute.getUuid() != null && attribute.getName() != null
                && attribute.getContentType() != null && attribute.getProperties() != null
                && attribute.getType() == AttributeType.META;
    }

    /**
     * Whether this answer describes the run at an earlier moment than one already applied. A connector that sends no
     * sequence at all is answered as ordered rather than dropped: the field is required, so its absence is a
     * non-conformant connector, and dropping every answer from one would leave the run with no status at all.
     */
    private static boolean arrivedOutOfOrder(Discovery run, DiscoveryStatusResponseDto status) {
        return status.getHighestSequence() != null && run.getConnectorHighestSequence() != null
                && status.getHighestSequence() < run.getConnectorHighestSequence();
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
                // Back off rather than keep the live cadence: a stopped run reports nothing new, and the reaper lets
                // one stay stopped for days. Polled at the live rung it would ask a paused connector the same question
                // every claim-floor for that whole window.
                workWriter
                        .reschedule(run.getUuid(), DiscoveryWorkType.STATUS, 0,
                                OffsetDateTime.now(ZoneOffset.UTC).plus(stoppedPollInterval));
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

    /**
     * What the connector says it has found, from the per-resource breakdown it reports alongside its work counters.
     * Absent when it reports no breakdown, in which case the run keeps whatever it last knew rather than being told it
     * has found nothing.
     */
    private static Optional<Integer> connectorCertificateYield(Discovery run) {
        return Optional
                .ofNullable(run.getProgress())
                .map(DiscoveryProgressDto::getByResource)
                .map(byResource -> byResource.get(Resource.CERTIFICATE))
                .map(DiscoveryResourceProgressDto::getProduced)
                .map(Long::intValue);
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
