package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.AttributeDefinitionUtils;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Opens and drives a v2 run at its connector.
 *
 * <p>
 * {@code start} is the handover, not the scan: it opens the run, records what the connector answered, schedules the
 * first agenda rows, and returns. Every failure there ends the run terminally — a non-terminal v2 run has no owner,
 * since the caller is asynchronous and the tick workers drive only runs that already have agenda rows.
 *
 * <p>
 * <b>The lifecycle operations behave the opposite way</b> and throw: they answer a waiting client, so an illegal
 * transition is a {@link ValidationException} (422) rather than a run outcome.
 */
@Component
public class DiscoveryProviderV2Adapter implements DiscoveryProviderAdapter {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryProviderV2Adapter.class);

    /**
     * The contract's cap on a serialized run handle. Enforced on every meta-returning response, because the handle is
     * replayed on every later call: accepting an oversized one would produce a run whose every tick sends a request the
     * transport cannot carry.
     */
    static final int MAX_META_BYTES = 64 * 1024;

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryMessageRepository messageRepository;
    private final DiscoveryDetailCounts detailCounts;
    private final ConnectorInterfaceRepository connectorInterfaceRepository;
    private final DiscoveryV2Client client;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryRunTerminator terminator;
    private final ConnectorCapabilityService capabilityService;
    private final TransactionHandler transactionHandler;
    private final DiscoveryWorkProperties workProperties;

    @PersistenceContext
    private EntityManager entityManager;

    @SuppressWarnings("java:S107")
    public DiscoveryProviderV2Adapter(DiscoveryRepository discoveryRepository,
            DiscoveryMessageRepository messageRepository, DiscoveryDetailCounts detailCounts,
            ConnectorInterfaceRepository connectorInterfaceRepository, DiscoveryV2Client client,
            DiscoveryWorkWriter workWriter, DiscoveryRunTerminator terminator,
            ConnectorCapabilityService capabilityService, TransactionHandler transactionHandler,
            DiscoveryWorkProperties workProperties) {
        this.discoveryRepository = discoveryRepository;
        this.messageRepository = messageRepository;
        this.detailCounts = detailCounts;
        this.connectorInterfaceRepository = connectorInterfaceRepository;
        this.client = client;
        this.workWriter = workWriter;
        this.terminator = terminator;
        this.capabilityService = capabilityService;
        this.transactionHandler = transactionHandler;
        this.workProperties = workProperties;
    }

    @Override
    public DiscoveryDetailDto start(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        Discovery run = transactionHandler
                .runInNewTransaction(() -> discoveryRepository.findByUuid(discoveryUuid).orElse(null));
        if (run == null) {
            // Routed here for a run that no longer exists: the refusal signal, so the caller ends it the same way
            // it ends any run it cannot dispatch, rather than this throwing into an async caller.
            throw new UnsupportedDiscoveryVersionException("Discovery " + discoveryUuid + " no longer exists");
        }
        try {
            // Outside any transaction, by DiscoveryV2Client's own NOT_SUPPORTED boundary.
            validateResources(run);
            DiscoveryInitiateResponseDto response = client.initiate(run);
            // Past this point the connector holds an open run, so every exit tells it to drop one it will never
            // be asked about again -- otherwise its scan keeps going until its own timeout, and the run is
            // terminal by then so the reaper will not collect it either.
            try {
                if (!recordInitiated(discoveryUuid, response, scheduledJobInfo)) {
                    logger
                            .info("Discovery {} ended while it was being started; dropping it at the connector",
                                    discoveryUuid);
                    dropAtConnector(run, response.getMeta());
                    return detailOf(discoveryUuid);
                }
                scheduleFirstTicks(discoveryUuid);
            } catch (Exception bookkeepingFailed) {
                dropAtConnector(run, response.getMeta());
                throw bookkeepingFailed;
            }
            return detailOf(discoveryUuid);
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logger.error("Discovery {} could not be started at its connector", discoveryUuid, e);
            terminator.endWith(discoveryUuid, failing -> {
                // Whoever asked for the run is still on the thread and reports this failure to the scheduler itself.
                // Announcing it here as well would finalize one job history twice: its owner notified twice, and
                // SCHEDULED_JOB_FINISHED raised twice, so anything bound to that event acts twice.
                failing.setScheduledJobHistoryUuid(null);
                return new DiscoveryRunTerminator.Ending(DiscoveryStatus.FAILED, startFailureReason(e));
            });
            return detailOf(discoveryUuid);
        }
    }

    /**
     * Refuses a run the connector cannot perform before opening it. The connector would reject the initiate anyway, but
     * a run that never opened is cheaper to explain than one that opened and failed, and the message names the resource
     * rather than relaying a connector error.
     */
    private void validateResources(Discovery run) throws Exception {
        List<Resource> requested = run.getResources() == null ? List.of() : run.getResources();
        if (requested.isEmpty()) {
            throw new RunRefusedException("the run targets no resources");
        }
        List<Resource> supported = client.supportedResources(run);
        List<Resource> unsupported = requested.stream().filter(resource -> !supported.contains(resource)).toList();
        if (!unsupported.isEmpty()) {
            throw new RunRefusedException(
                    "the connector does not discover " + unsupported.stream().map(Resource::getLabel).toList());
        }
    }

    /**
     * Records what the connector answered, under the run's lock.
     *
     * @return whether the run was still live to record against; {@code false} when it ended while the connector was
     * being called, which leaves the caller to drop the now-orphaned connector-side run
     * @throws IllegalStateException if the handle exceeds the cap — thrown before anything is persisted, so the run
     * fails rather than being driven with a handle it cannot replay
     */
    private boolean recordInitiated(UUID discoveryUuid, DiscoveryInitiateResponseDto response,
            ScheduledJobInfo scheduledJobInfo) {
        return Boolean.TRUE.equals(transactionHandler.runInNewTransaction(() -> {
            Discovery locked = discoveryRepository
                    .findWithLockByUuid(discoveryUuid)
                    .orElseThrow(() -> new IllegalStateException("Discovery " + discoveryUuid + " vanished mid-start"));
            // Re-asserted under the lock, as DiscoveryRunTerminator.endIf does. The run was created IN_PROGRESS and
            // started asynchronously, so a cancel in that window has already told the connector to drop it and
            // deleted the agenda; writing IN_PROGRESS here would revive a run nothing can drive.
            if (DiscoveryRunLifecycle.isTerminal(locked.getStatus())) {
                return false;
            }
            enforceMetaCap(response.getMeta());
            locked.setRunMeta(response.getMeta());
            locked.setStoppable(stoppable(locked, response));
            locked.setStatus(DiscoveryStatus.IN_PROGRESS);
            locked.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
            locked.setStartTime(OffsetDateTime.now(ZoneOffset.UTC));
            // Stored because the run ends much later, in a tick worker that no longer has these: without them
            // the scheduled job never learns the outcome and hangs open.
            if (scheduledJobInfo != null) {
                locked.setScheduledJobHistoryUuid(scheduledJobInfo.jobHistoryUuid());
            }
            discoveryRepository.save(locked);
            return true;
        }));
    }

    /**
     * Tells the connector to drop a run it opened that Core will never drive — a start that failed after initiate
     * succeeded, or one the caller cancelled while initiate was in flight. Best effort, and against a detached entity:
     * the handle is restored only to address the call, never to be written back.
     */
    private void dropAtConnector(Discovery run, List<MetadataAttribute> meta) {
        try {
            run.setRunMeta(meta);
            client.cancel(run);
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logger
                    .warn("Could not drop discovery {} at its connector; its scan may keep running until the "
                            + "connector's own timeout", run.getUuid(), e);
        }
    }

    private static void enforceMetaCap(List<MetadataAttribute> meta) {
        int size = metaSize(meta);
        if (size > MAX_META_BYTES) {
            throw new RunRefusedException("meta size exceeded: " + size + " bytes, cap " + MAX_META_BYTES);
        }
    }

    private static boolean exceedsMetaCap(List<MetadataAttribute> meta) {
        return metaSize(meta) > MAX_META_BYTES;
    }

    private static int metaSize(List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return 0;
        }
        String serialized = AttributeDefinitionUtils.serialize(meta);
        return serialized == null ? 0 : serialized.getBytes(StandardCharsets.UTF_8).length;
    }

    /**
     * Disposes of a run whose connector has already acted on a request Core cannot record: the handle it answered with
     * is too large to replay, so every later call would send a request the transport cannot carry.
     *
     * <p>
     * Rolling the local write back instead would leave Core describing a state the connector has left — paused while it
     * scans, or scanning while it is paused — and no tick reconciles that, since a stopped run is restarted only by an
     * explicit resume. The run ends, and the connector is told to drop it.
     */
    private void endUndriveable(Discovery run, String operation, List<MetadataAttribute> meta) {
        logger
                .error("Discovery {} answered {} with a handle of {} bytes, over the {} byte cap; ending the run",
                        run.getUuid(), operation, metaSize(meta), MAX_META_BYTES);
        terminator
                .end(run.getUuid(), DiscoveryStatus.FAILED,
                        "The connector's run handle is too large to replay, so the run cannot be driven further");
        dropAtConnector(run, meta);
    }

    /**
     * The connector may only narrow the interface-level {@code discoveryStopResume} flag, never widen it: claiming a
     * stoppable run without advertising the capability is a contract violation, and Core clamps rather than trusting
     * it. Undeclared falls back to the flag alone.
     */
    private boolean stoppable(Discovery run, DiscoveryInitiateResponseDto response) {
        ConnectorInterfaceEntity iface = run.getConnectorInterfaceUuid() == null
                ? null
                : connectorInterfaceRepository.findById(run.getConnectorInterfaceUuid()).orElse(null);
        boolean advertised = capabilityService.supports(iface, FeatureFlag.DISCOVERY_STOP_RESUME);
        return advertised && !Boolean.FALSE.equals(response.getStoppable());
    }

    /**
     * A run needs both agenda rows from the outset: STATUS reports progress and terminality, DRAIN pulls results. The
     * first delay of each ladder applies rather than now — a due-now row could be claimed by the sweep before this
     * transaction commits.
     */
    private void scheduleFirstTicks(UUID discoveryUuid) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        for (DiscoveryWorkType type : List.of(DiscoveryWorkType.STATUS, DiscoveryWorkType.DRAIN)) {
            workWriter.schedule(discoveryUuid, type, now.plus(workProperties.scheduleFor(type).delays().getFirst()));
        }
    }

    /**
     * The run's message is a user-visible surface, so only Core-authored text reaches it.
     *
     * <p>
     * A connector failure is described through {@link DiscoveryConnectorErrors#describe}, which maps the closed
     * error-code vocabulary to text Core wrote and leaves the connector's own {@code detail} in the log. The validation
     * failures raised above this point are Core-authored already and pass through as they are.
     */
    // Package-private, like MAX_META_BYTES above: the rule about which text may reach the run is worth
    // asserting directly, and it cannot be reached through start() -- every failure a connector stub can
    // provoke arrives as a ConnectorException, which is the branch that was never in question.
    static String startFailureReason(Exception e) {
        // Only text Core wrote reaches the run, which publishes this on the detail and in the message log.
        //
        // A connector failure is named from the closed vocabulary in DiscoveryConnectorErrors rather than through
        // safeMessage: ConnectorException is a PlatformException, so safeMessage would pass the connector's own
        // prose, which is the thing that must not reach a user-visible field. Everything else goes through the
        // platform's gate, which admits a message only from an exception Core shaped -- an NPE's field path or a
        // driver's SQL is not one, and is left to the log above, which already has the exception itself.
        String reason = e instanceof ConnectorException || e instanceof ValidationException
                ? DiscoveryConnectorErrors.describe(e)
                : PlatformException.safeMessage(e, "");
        return reason == null || reason.isBlank()
                ? "Discovery could not be started at its connector"
                : "Discovery could not be started at its connector: " + reason;
    }

    /**
     * A run Core itself refused — for targeting nothing, for targeting what the connector does not discover, or for a
     * handle too large to replay. {@link PlatformException} is what marks its message as Core-authored, and so
     * publishable on the run; an {@link IllegalStateException} still, so the paths that catch one are unaffected.
     */
    private static final class RunRefusedException extends IllegalStateException implements PlatformException {
        private RunRefusedException(String message) {
            super(message);
        }
    }

    private DiscoveryDetailDto detailOf(UUID discoveryUuid) {
        return transactionHandler
                .runInNewTransaction(() -> discoveryRepository
                        .findByUuid(discoveryUuid)
                        .map(run -> DiscoveryDtoMapper.toDetailDto(run, detailCounts.forRun(run)))
                        .orElse(null));
    }

    @Override
    public void stop(Discovery discovery) throws ConnectorException {
        requireStatus(discovery, "stopped", DiscoveryStatus.IN_PROGRESS);
        // Both gates: the interface must advertise the capability, and this run must have been declared stoppable
        // at initiate. A run that was never checkpointable cannot be stopped even by a connector that can stop others.
        if (!advertisesStopResume(discovery) || !Boolean.TRUE.equals(discovery.getStoppable())) {
            throw new ValidationException("Discovery " + discovery.getUuid() + " cannot be stopped");
        }
        UUID discoveryUuid = discovery.getUuid();
        DiscoveryStopResponseDto response = call(discoveryUuid, "stop", () -> client.stop(discovery));
        // The connector has already stopped: the run is disposed of rather than rolled back over it.
        if (exceedsMetaCap(response.getMeta())) {
            endUndriveable(discovery, "stop", response.getMeta());
            return;
        }
        transactionHandler.runInNewTransaction(() -> {
            Discovery locked = lock(discoveryUuid);
            // The status checked before the connector call was a snapshot; the call can take tens of seconds, and a
            // tick worker or the reaper may have ended the run since. Writing STOPPED over that would resurrect it.
            requireStatus(locked, "stopped", DiscoveryStatus.IN_PROGRESS);
            locked.setRunMeta(response.getMeta());
            locked.setStatus(DiscoveryStatus.STOPPED);
            // Both, always together: connector_status is the connector's view of the run, and the connector has
            // just acknowledged the stop. Left behind it keeps reporting IN_PROGRESS for a run nobody is scanning.
            locked.setConnectorStatus(DiscoveryStatus.STOPPED);
            locked.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
            discoveryRepository.save(locked);
            // Best-effort, not atomic with the status above: resetAttempt is REQUIRES_NEW, so a failure after it
            // leaves a refreshed budget on a run that never reached STOPPED -- harmless, the budget is a retry
            // allowance rather than state. To the ceiling, not 0, so the budget is restored without restarting the
            // ramp at full speed. The agenda stays, parked -- a stopped run is resumable.
            workWriter
                    .resetAttempt(discoveryUuid, DiscoveryWorkType.STATUS,
                            workProperties.scheduleFor(DiscoveryWorkType.STATUS).ceilingAttempt());
            workWriter
                    .resetAttempt(discoveryUuid, DiscoveryWorkType.DRAIN,
                            workProperties.scheduleFor(DiscoveryWorkType.DRAIN).ceilingAttempt());
            return locked;
        });
    }

    @Override
    public void resume(Discovery discovery) throws ConnectorException {
        requireStatus(discovery, "resumed", DiscoveryStatus.STOPPED);
        // The flag alone, deliberately: the run's own snapshot describes whether it could be stopped, and the
        // connector's 410 is the authority on whether its checkpoint still exists.
        if (!advertisesStopResume(discovery)) {
            throw new ValidationException("Discovery " + discovery.getUuid() + " cannot be resumed");
        }
        UUID discoveryUuid = discovery.getUuid();
        DiscoveryInitiateResponseDto response;
        try {
            response = call(discoveryUuid, "resume", () -> client.resume(discovery));
        } catch (ValidationException | ConnectorException e) {
            // A lost checkpoint is not an error to answer with: the run can never be driven again, so it is disposed
            // of here rather than reported. Every other refusal keeps the shape call() gave it.
            if (isCheckpointLost(e)) {
                disposeCheckpointLost(discoveryUuid);
                return;
            }
            throw e;
        }
        // As in stop, and the direction that cannot repair itself: nothing but an explicit resume restarts a
        // stopped run, so the divergence would stand until the reaper cancelled it days later.
        if (exceedsMetaCap(response.getMeta())) {
            endUndriveable(discovery, "resume", response.getMeta());
            return;
        }
        transactionHandler.runInNewTransaction(() -> {
            Discovery locked = lock(discoveryUuid);
            // Same reason as stop: the legality check ran against a snapshot taken before the connector call.
            requireStatus(locked, "resumed", DiscoveryStatus.STOPPED);
            locked.setRunMeta(response.getMeta());
            locked.setStoppable(stoppable(locked, response));
            locked.setStatus(DiscoveryStatus.IN_PROGRESS);
            locked.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
            locked.setStoppedAt(null);
            return discoveryRepository.save(locked);
        });
        workWriter.expedite(discoveryUuid, DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC));
        workWriter.expedite(discoveryUuid, DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Override
    public void cancel(Discovery discovery) throws ConnectorException {
        requireStatus(discovery, "cancelled", DiscoveryStatus.IN_PROGRESS, DiscoveryStatus.STOPPED);
        UUID discoveryUuid = discovery.getUuid();
        // 404 is not a failure: it says the connector no longer tracks the run, which is the state cancel asked
        // for. The client hands the status back rather than throwing precisely so this can be read, not caught.
        call(discoveryUuid, "cancel", () -> client.cancel(discovery));
        // Through the decide hook so connector_status and the terminal transition commit under one lock: split, the
        // run is non-terminal between the two commits and a status tick in that window overwrites this. Set here
        // rather than in the terminator, which also ends runs whose connector said nothing and must leave its last
        // known view standing; this cancel was acknowledged.
        terminator.endWith(discoveryUuid, run -> {
            run.setConnectorStatus(DiscoveryStatus.CANCELLED);
            return new DiscoveryRunTerminator.Ending(DiscoveryStatus.CANCELLED, "Discovery cancelled");
        });
    }

    /**
     * A resume the connector cannot honour: its checkpoint is gone, so the run can never be driven again.
     *
     * <p>
     * The staged items stay. They were really discovered, and a client can still read them — they are simply never
     * processed, because the run that would have processed them no longer exists.
     */
    private void disposeCheckpointLost(UUID discoveryUuid) {
        logger.warn("Discovery {} cannot be resumed: the connector no longer holds its checkpoint", discoveryUuid);
        terminator.end(discoveryUuid, DiscoveryStatus.FAILED, "checkpoint lost");
    }

    /**
     * A resume the connector cannot honour: either it no longer tracks the run at all, or it still does but its
     * checkpoint is gone. {@link DiscoveryConnectorErrors#isRunNoLongerTracked} already covers the first, including the
     * bodiless 404 that arrives as a plain {@code ConnectorEntityNotFoundException} over the AMQP proxy; the second is
     * the contract's 410.
     *
     * <p>
     * Compared as an int rather than through {@code HttpStatus.valueOf}, which throws on a valid-but-unmapped code and
     * would replace the connector's error with an opaque failure of our own.
     */
    private static boolean isCheckpointLost(Exception e) {
        if (DiscoveryConnectorErrors.isRunNoLongerTracked(e)) {
            return true;
        }
        return e instanceof ConnectorProblemException problem && problem.getProblemDetail() != null
                && problem.getProblemDetail().getStatus() == HttpStatus.GONE.value();
    }

    private void requireStatus(Discovery discovery, String verb, DiscoveryStatus... legal) {
        // Compared by identity rather than List.contains: the status column is nullable, and an immutable list
        // throws on a null argument instead of answering false.
        if (Arrays.stream(legal).noneMatch(status -> status == discovery.getStatus())) {
            // 422 rather than 409: the platform's state-transition convention, and Core maps no CONFLICT for run state.
            // getLabel, not the enum: this reaches a person. Null renders as a phrase rather than the word "null",
            // for the same nullable column the comment above guards against.
            String state = discovery.getStatus() == null ? "in an unknown state" : discovery.getStatus().getLabel();
            throw new ValidationException(
                    "Discovery " + discovery.getUuid() + " is " + state + " and cannot be " + verb);
        }
    }

    private boolean advertisesStopResume(Discovery discovery) {
        ConnectorInterfaceEntity iface = discovery.getConnectorInterfaceUuid() == null
                ? null
                : connectorInterfaceRepository.findById(discovery.getConnectorInterfaceUuid()).orElse(null);
        return capabilityService.supports(iface, FeatureFlag.DISCOVERY_STOP_RESUME);
    }

    /**
     * Takes the run's row lock and reads the row as it now is.
     *
     * <p>
     * The refresh is what makes the re-assertions above this call mean anything. Every lifecycle operation runs
     * {@code NOT_SUPPORTED} and has already loaded the run, so the locking read finds that same instance in the shared
     * persistence context and answers with its pre-call field values, however far the row has moved since.
     */
    private Discovery lock(UUID discoveryUuid) {
        Discovery run = discoveryRepository
                .findWithLockByUuid(discoveryUuid)
                .orElseThrow(() -> new IllegalStateException("Discovery " + discoveryUuid + " vanished mid-operation"));
        entityManager.refresh(run);
        return run;
    }

    /**
     * Runs a connector call, letting anything the platform already maps to a status pass through untouched and wrapping
     * only the genuinely unexpected.
     *
     * <p>
     * A conformant connector's refusal is a {@code ConnectorProblemException} over REST and a
     * {@link ValidationException} over MQ, and {@code ExceptionHandlingAdvice} maps both — as it maps a connector being
     * unreachable or broken. Wrapping them would turn each into a 500, answering the same refusal differently depending
     * on the transport underneath.
     */
    private <T> T call(UUID discoveryUuid, String operation, ConnectorCall<T> connectorCall) throws ConnectorException {
        try {
            return connectorCall.execute();
        } catch (ValidationException | ConnectorException e) {
            throw e;
        } catch (Exception e) {
            throw failed(discoveryUuid, operation, e);
        }
    }

    private IllegalStateException failed(UUID discoveryUuid, String operation, Exception e) {
        if (e instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
        logger.error("Discovery {} {} failed at its connector", discoveryUuid, operation, e);
        return new IllegalStateException("Discovery " + operation + " failed at its connector", e);
    }

    @FunctionalInterface
    private interface ConnectorCall<T> {
        T execute() throws Exception;
    }
}
