package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * Terminates discovery v2 runs the tick engine can no longer drive:
 *
 * <ul>
 * <li><b>Work lost</b> — an actively driven v2 run with no agenda rows never receives another tick, so nothing would
 * ever end it. Runs younger than {@code reap-grace} are skipped: the initiate window legitimately has the run row
 * before its first agenda rows. {@code STOPPED} runs are deliberately exempt — failing one for lost agenda rows would
 * destroy a checkpoint the stop-expiry path still allows to resume.</li>
 * <li><b>Stop expired</b> — a {@code STOPPED} run not resumed within {@code stopped-max-duration} is cancelled; the
 * connector's checkpoint can no longer be assumed to exist. The connector-side cancel is best-effort and fires only
 * after the terminal transition has committed, replaying a pre-wipe snapshot of the run context.</li>
 * </ul>
 *
 * <p>
 * Runs as a phase of {@link DiscoveryWorkSweeper#sweep()} (no separate schedule) and reuses that sweep's
 * {@code DISCOVERY_WORK_SWEEP} advisory lock for selection. Correctness across nodes rests on the per-run pessimistic
 * lock plus a re-assertion of the reap condition; the advisory lock only avoids redundant selection.
 * </p>
 */
@Component
public class DiscoveryRunReaper {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryRunReaper.class);

    private static final List<DiscoveryStatus> WORK_DRIVEN_STATUSES = List
            .of(DiscoveryStatus.IN_PROGRESS, DiscoveryStatus.PROCESSING);

    // One bounded batch per reap condition per sweep, kept small because each reaped run can cost a
    // synchronous connector cancel on the sweep thread: the worst-case stall is this many connector
    // timeouts. The sweep cadence drains any backlog.
    private static final int REAP_BATCH_SIZE = 10;

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryWorkRepository workRepository;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryV2Client discoveryV2Client;
    private final ConnectorInterfaceRepository connectorInterfaceRepository;
    private final TransactionHandler transactionHandler;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final DiscoveryRunTerminator terminator;
    private final Duration reapGrace;
    private final Duration stoppedMaxDuration;

    public DiscoveryRunReaper(DiscoveryRepository discoveryRepository, DiscoveryWorkRepository workRepository,
            DiscoveryWorkWriter workWriter, DiscoveryV2Client discoveryV2Client,
            ConnectorInterfaceRepository connectorInterfaceRepository, TransactionHandler transactionHandler,
            ClusterOperationSynchronizer clusterSynchronizer, DiscoveryRunTerminator terminator,
            @Value("${discovery.work.reap-grace:PT5M}") Duration reapGrace,
            @Value("${discovery.run.stopped-max-duration:P7D}") Duration stoppedMaxDuration) {
        this.discoveryRepository = discoveryRepository;
        this.workRepository = workRepository;
        this.workWriter = workWriter;
        this.discoveryV2Client = discoveryV2Client;
        this.connectorInterfaceRepository = connectorInterfaceRepository;
        this.transactionHandler = transactionHandler;
        this.clusterSynchronizer = clusterSynchronizer;
        this.terminator = terminator;
        this.reapGrace = reapGrace;
        this.stoppedMaxDuration = stoppedMaxDuration;
    }

    /**
     * Selects one bounded batch per reap condition under the shared advisory lock, then handles each run in its own
     * transaction outside the lock. One batch per sweep is sufficient: the sweep cadence drains any backlog, and a run
     * is not a candidate until its grace or expiry window has passed.
     */
    public void reap() {
        int failed = 0;
        for (UUID uuid : selectUnderSweepLock(this::selectWorkLost)) {
            if (failWorkLost(uuid)) {
                failed++;
            }
        }
        int cancelled = 0;
        for (UUID uuid : selectUnderSweepLock(this::selectStopExpired)) {
            if (cancelExpiredStop(uuid)) {
                cancelled++;
            }
        }
        if (failed > 0 || cancelled > 0) {
            logger.info("Discovery run reap: {} failed (work lost), {} cancelled (stop expired)", failed, cancelled);
        }
    }

    private List<UUID> selectUnderSweepLock(Supplier<List<UUID>> selection) {
        return transactionHandler.runInNewTransaction(() -> {
            if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP)) {
                return List.of();
            }
            return selection.get();
        });
    }

    private List<UUID> selectWorkLost() {
        OffsetDateTime threshold = OffsetDateTime.now(ZoneOffset.UTC).minus(reapGrace);
        return discoveryRepository
                .findWorkLostRunUuids(WORK_DRIVEN_STATUSES, threshold, PageRequest.of(0, REAP_BATCH_SIZE));
    }

    private List<UUID> selectStopExpired() {
        OffsetDateTime threshold = OffsetDateTime.now(ZoneOffset.UTC).minus(stoppedMaxDuration);
        return discoveryRepository.findExpiredStoppedRunUuids(threshold, PageRequest.of(0, REAP_BATCH_SIZE));
    }

    private boolean failWorkLost(UUID uuid) {
        try {
            ReapedRun reaped = transactionHandler.runInNewTransaction(() -> {
                Discovery run = discoveryRepository.findWithLockByUuid(uuid).orElse(null);
                // Re-assert under the row lock: the run may have finished, or gained agenda rows,
                // between selection and locking.
                if (run == null || !WORK_DRIVEN_STATUSES.contains(run.getStatus())
                        || workRepository.existsByDiscoveryUuid(uuid)) {
                    return null;
                }
                List<MetadataAttribute> meta = run.getRunMeta();
                endRun(run, DiscoveryStatus.FAILED, "Discovery work lost; the run can no longer be driven");
                return new ReapedRun(run, meta);
            });
            if (reaped == null) {
                return false;
            }
            // Sent even with no handle to replay: control calls are addressed by runId, with meta optional, so a
            // connector that started scanning before the handle was persisted can still be told to stop.
            bestEffortConnectorCancel(reaped);
            return true;
        } catch (RuntimeException e) {
            // One run's failure (e.g. a lock timeout) must not abort the rest of the batch.
            logger.warn("Failed to reap work-lost discovery run {}", uuid, e);
            return false;
        }
    }

    private boolean cancelExpiredStop(UUID uuid) {
        OffsetDateTime threshold = OffsetDateTime.now(ZoneOffset.UTC).minus(stoppedMaxDuration);
        try {
            ReapedRun reaped = transactionHandler.runInNewTransaction(() -> {
                Discovery run = discoveryRepository.findWithLockByUuid(uuid).orElse(null);
                // Re-assert under the row lock: the run may have been resumed or finished in the meantime.
                if (run == null || !isStopExpired(run, threshold)) {
                    return null;
                }
                List<MetadataAttribute> meta = run.getRunMeta();
                endRun(run, DiscoveryStatus.CANCELLED, "Stop expired: the run was not resumed in time");
                workWriter.deleteForRun(uuid);
                return new ReapedRun(run, meta);
            });
            if (reaped == null) {
                return false;
            }
            bestEffortConnectorCancel(reaped);
            return true;
        } catch (RuntimeException e) {
            logger.warn("Failed to cancel expired stopped discovery run {}", uuid, e);
            return false;
        }
    }

    private static boolean isStopExpired(Discovery run, OffsetDateTime threshold) {
        return run.getStatus() == DiscoveryStatus.STOPPED && run.getStoppedAt() != null
                && run.getStoppedAt().isBefore(threshold);
    }

    /**
     * Tells the connector to drop the run, strictly after the terminal transition has committed — the permanently safe
     * moment: a terminal run can no longer be resumed, so the cancel cannot race a revival. The entity is detached
     * here, so restoring the pre-wipe meta snapshot only feeds the cancel call, never the database. A failure is only a
     * warning: a scan the connector was not told to drop keeps running until its own timeout.
     *
     * <p>
     * Goes to the client rather than through the provider adapter. The adapter's {@code cancel} is the operation a
     * client asks for and refuses anything already terminal — which every run reaching here is, by construction. This
     * is a notification, not that operation.
     */
    private void bestEffortConnectorCancel(ReapedRun reaped) {
        if (!drivesV2(reaped.run())) {
            // A v1 run has no cancel to send -- its provider call is synchronous and already over -- and a
            // generation this platform cannot drive has no client to send one with.
            return;
        }
        try {
            reaped.run().setRunMeta(reaped.meta());
            discoveryV2Client.cancel(reaped.run());
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logger
                    .warn("Best-effort connector cancel failed for discovery run {}; the connector-side scan may keep "
                            + "running until its own timeout", reaped.run().getUuid(), e);
        }
    }

    private boolean drivesV2(Discovery run) {
        return run.getConnectorInterfaceUuid() != null && connectorInterfaceRepository
                .findById(run.getConnectorInterfaceUuid())
                .map(iface -> "v2".equals(iface.getVersion()))
                .orElse(false);
    }

    /**
     * A run whose terminal transition has committed, plus the pre-wipe run context the connector cancel replays.
     */
    private record ReapedRun(Discovery run, List<MetadataAttribute> meta) {
    }

    /**
     * Ends the run through the terminator's own mutation, so a reaped run is indistinguishable from one a worker ended
     * — same status, same released handle, same entry in the message log. The re-assert and the row lock stay here:
     * they are the reaper's conditions, not the terminator's.
     *
     * <p>
     * {@code connectorStatus} is deliberately left at the last report: the connector never confirmed this ending.
     */
    private void endRun(Discovery run, DiscoveryStatus status, String message) {
        terminator.applyTerminalState(run, status, message);
    }
}
