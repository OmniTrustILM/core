package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import com.otilm.core.tasks.ScheduledJobInfo;
import java.util.UUID;

/**
 * The version seam for discovery provider interaction: one implementation per connector discovery interface generation,
 * selected by {@link DiscoveryProviderAdapterFactory}.
 *
 * <p>
 * {@code start} takes the run's uuid rather than the entity: the v1 flow reloads the run with its associations inside
 * its own transaction boundaries, because it executes asynchronously in a different session than the one that created
 * the run.
 *
 * <p>
 * Lifecycle refusals carry meaning: {@code UnsupportedOperationException} means the connector generation can never
 * perform the operation (callers map it to the contract's 422); an adapter whose implementation is merely pending
 * signals that with {@link IllegalStateException} instead — a defect, not part of this contract.
 */
public interface DiscoveryProviderAdapter {

    /**
     * Runs the whole provider-side discovery for the run, returning the run detail at handoff or completion.
     *
     * @throws UnsupportedDiscoveryVersionException when the run cannot be dispatched to this adapter after all — the
     * routing-refusal signal {@code runDiscovery} converts into a terminal FAILED run rather than an escaping
     * exception.
     */
    DiscoveryDetailDto start(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo);

    /**
     * Starts the run for a caller still waiting on its create. A connector's refusal of what was asked is theirs to
     * correct, so it is thrown to them and the refused run is discarded rather than left behind FAILED; any other
     * failure ends the run as {@link #start} does.
     *
     * @throws ConnectorProblemException when the connector refused the run's configuration
     * @throws UnsupportedOperationException when the generation's start runs the whole discovery on the calling thread,
     * as v1's does, which no caller may wait on
     * @throws UnsupportedDiscoveryVersionException as {@link #start} does
     */
    default DiscoveryDetailDto startForCaller(UUID discoveryUuid) throws ConnectorProblemException {
        throw new UnsupportedOperationException("This discovery generation starts its runs asynchronously");
    }

    /**
     * @throws UnsupportedOperationException when the connector version can never suspend a run (v1 cannot)
     */
    void stop(Discovery discovery) throws ConnectorException;

    /**
     * @throws UnsupportedOperationException when the connector version can never resume a run (v1 cannot)
     */
    void resume(Discovery discovery) throws ConnectorException;

    /**
     * @throws UnsupportedOperationException when the connector version can never cancel a run (v1 cannot)
     */
    void cancel(Discovery discovery) throws ConnectorException;
}
