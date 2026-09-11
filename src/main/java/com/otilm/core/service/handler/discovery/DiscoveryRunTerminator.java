package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResourceProgressDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Ends a discovery v2 run, the one way every tick worker does it: sets the status and reason, releases the connector
 * handle, and deletes the run's agenda.
 */
@Component
public class DiscoveryRunTerminator {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryRunTerminator.class);

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryMessageWriter messageWriter;
    private final TransactionHandler transactionHandler;
    private final ApplicationEventPublisher eventPublisher;
    private final ScheduledJobHistoryRepository scheduledJobHistoryRepository;
    private final DiscoveryCertificateRepository certificateRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public DiscoveryRunTerminator(DiscoveryRepository discoveryRepository, DiscoveryWorkWriter workWriter,
            DiscoveryMessageWriter messageWriter, TransactionHandler transactionHandler,
            ApplicationEventPublisher eventPublisher, ScheduledJobHistoryRepository scheduledJobHistoryRepository,
            DiscoveryCertificateRepository certificateRepository) {
        this.discoveryRepository = discoveryRepository;
        this.workWriter = workWriter;
        this.messageWriter = messageWriter;
        this.transactionHandler = transactionHandler;
        this.eventPublisher = eventPublisher;
        this.scheduledJobHistoryRepository = scheduledJobHistoryRepository;
        this.certificateRepository = certificateRepository;
    }

    /**
     * Ends a run on the strength of something the connector said, refusing one that has already left the connector —
     * unlike {@link #end}, which accepts a run already {@code PROCESSING}.
     */
    public boolean endConnectorOwned(UUID discoveryUuid, DiscoveryStatus status, String reason) {
        return endIf(discoveryUuid, DiscoveryRunLifecycle::hasLeftTheConnector, run -> new Ending(status, reason));
    }

    /**
     * Ends a run, accepting even one already {@code PROCESSING} — processing itself legitimately ends a run, unlike the
     * connector-driven ending in {@link #endConnectorOwned}.
     */
    public boolean end(UUID discoveryUuid, DiscoveryStatus status, String reason) {
        return endIf(discoveryUuid, DiscoveryRunLifecycle::isTerminal, run -> new Ending(status, reason));
    }

    /**
     * Ends a run on a decision taken under the run row's lock, against the locked entity.
     *
     * @param decide the ending to apply, or {@code null} to leave the run alone
     * @return whether this call was the one that ended the run
     */
    public boolean endWith(UUID discoveryUuid, Function<Discovery, Ending> decide) {
        return endIf(discoveryUuid, DiscoveryRunLifecycle::isTerminal, decide);
    }

    /**
     * @param alreadyPast states from which this ending is no longer the caller's to make
     */
    private boolean endIf(UUID discoveryUuid, Predicate<DiscoveryStatus> alreadyPast,
            Function<Discovery, Ending> decide) {
        return Boolean.TRUE.equals(transactionHandler.runInNewTransaction(() -> {
            Discovery run = discoveryRepository.findWithLockByUuid(discoveryUuid).orElse(null);
            if (run == null) {
                return false;
            }
            // The lock alone proves nothing here. A lifecycle call runs NOT_SUPPORTED with the run already loaded,
            // so this read finds that same instance and answers with its pre-call fields -- the guard below would
            // miss an ending committed while the connector call was in flight, and the write would then rebuild
            // every column from the stale snapshot, since Discovery is not @DynamicUpdate.
            entityManager.refresh(run);
            if (alreadyPast.test(run.getStatus())) {
                logger.debug("Discovery {} is already {}; leaving it alone", discoveryUuid, run.getStatus());
                return false;
            }
            Ending ending = decide.apply(run);
            if (ending == null) {
                logger.debug("Discovery {} is not ready to end after all; leaving it alone", discoveryUuid);
                return false;
            }
            applyTerminalState(run, ending.status(), ending.reason());
            workWriter.deleteForRun(discoveryUuid);
            return true;
        }));
    }

    /** The status and reason a run ends with. */
    public record Ending(DiscoveryStatus status, String reason) {
    }

    /**
     * Applies the terminal state without opening a transaction, for callers (the reaper, and the status tick) that
     * already hold the run row's lock and would deadlock against {@link #end}'s own.
     */
    public void applyTerminalState(Discovery run, DiscoveryStatus status, String reason) {
        run.setStatus(status);
        run.setMessage(reason);
        run.setEndTime(OffsetDateTime.now(ZoneOffset.UTC));
        recordCertificateCounts(run);
        run.setRunMeta(null);
        messageWriter.appendRunEnded(run.getUuid(), DiscoveryRunLifecycle.severityOf(status), reason);
        logger.info("Discovery {} ended as {}: {}", run.getUuid(), status, reason);
        announceEnding(run, status, reason);
    }

    /**
     * Fills the two certificate counters the v1 adapter fills at the end of its own run, so both generations report the
     * same numbers to the same clients. Counted from the staging rows at the end rather than accumulated as the ticks
     * go, so a retried tick needs no reconciliation.
     */
    private void recordCertificateCounts(Discovery run) {
        run.setTotalCertificatesDiscovered(certificateRepository.countByDiscovery(run).intValue());
        connectorCertificateYield(run).ifPresent(run::setConnectorTotalCertificatesDiscovered);
    }

    /**
     * Certificates the connector said it produced, from its last progress report. Absent when it does not attribute
     * yield by resource, in which case the counter is left alone rather than zeroed: Core never learned the number.
     */
    private static Optional<Integer> connectorCertificateYield(Discovery run) {
        return Optional
                .ofNullable(run.getProgress())
                .map(DiscoveryProgressDto::getByResource)
                .map(byResource -> byResource.get(Resource.CERTIFICATE))
                .map(DiscoveryResourceProgressDto::getProduced)
                .map(Long::intValue);
    }

    /**
     * Announces the ending on the same event a v1 run raises, so triggers, notification and the scheduler reach both
     * generations alike. The handler applies a terminal status only to a run that is not already terminal, so this
     * ending stands as written and only the follow-ups are dispatched.
     *
     * <p>
     * Published through the event bus rather than the producer because the listener is {@code AFTER_COMMIT}: this runs
     * while holding the run's row, and a rolled-back ending must not announce itself.
     */
    private void announceEnding(Discovery run, DiscoveryStatus status, String reason) {
        eventPublisher
                .publishEvent(DiscoveryFinishedEventHandler
                        .constructEventMessage(run.getUuid(), run.getStartedByUserUuid(), scheduledJobOf(run),
                                new DiscoveryResult(status, reason)));
    }

    /**
     * Rebuilt from the one execution uuid the run stored; the history row carries the job, and the scheduler resolves
     * the name from it, so neither is kept as a second copy. A history row that no longer exists yields no job info at
     * all: passing the uuid on would hand the scheduler an execution it cannot find, turning a clean ending into a
     * downstream failure.
     */
    private ScheduledJobInfo scheduledJobOf(Discovery run) {
        if (run.getScheduledJobHistoryUuid() == null) {
            return null;
        }
        return scheduledJobHistoryRepository
                .findById(run.getScheduledJobHistoryUuid())
                .map(history -> new ScheduledJobInfo(null, history.getScheduledJobUuid(), history.getUuid()))
                .orElseGet(() -> {
                    logger
                            .warn("Discovery {} references scheduled job execution {}, which no longer exists; "
                                    + "its ending is not reported to the scheduler", run.getUuid(),
                                    run.getScheduledJobHistoryUuid());
                    return null;
                });
    }
}
