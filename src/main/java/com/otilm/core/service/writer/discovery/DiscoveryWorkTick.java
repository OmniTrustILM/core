package com.otilm.core.service.writer.discovery;

import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * One admitted run of a discovery tick, holding the lease on its {@code discovery_work} row. Every write the tick makes
 * to its own row goes through here, so it applies only while the row is still leased to this tick.
 *
 * <p>
 * A tick ends <em>resolved</em> once it has said what happens to its row next: rescheduled it, released it, or handed
 * it to a continuation. The listener reschedules an unresolved tick to its next rung. A write made inside a transaction
 * resolves the tick only when that transaction commits, so a rolled-back decision still leaves the row to the listener.
 * Not thread-safe: one tick runs on one listener thread.
 */
public final class DiscoveryWorkTick {

    private final DiscoveryWorkLease lease;
    private final UUID discoveryUuid;
    private final DiscoveryWorkType workType;
    private final int attempt;
    private final UUID token;
    private boolean resolved;

    DiscoveryWorkTick(DiscoveryWorkLease lease, UUID discoveryUuid, DiscoveryWorkType workType, int attempt,
            UUID token) {
        this.lease = lease;
        this.discoveryUuid = discoveryUuid;
        this.workType = workType;
        this.attempt = attempt;
        this.token = token;
    }

    public UUID discoveryUuid() {
        return discoveryUuid;
    }

    public DiscoveryWorkType workType() {
        return workType;
    }

    /** The row's attempt counter when this tick was claimed, before the claim charged it. */
    public int attempt() {
        return attempt;
    }

    public UUID token() {
        return token;
    }

    /**
     * Extends the lease, so the sweep does not reclaim the row while this tick is still working it.
     *
     * @return false once another tick, a lifecycle change or a deletion took the row: nothing this tick does to it
     * lands any more, so the caller stops
     */
    public boolean renew() {
        return lease.renew(this);
    }

    /** Schedules the row's next tick and frees the row. */
    public void reschedule(int nextAttempt, OffsetDateTime nextDueAt) {
        lease.reschedule(this, nextAttempt, nextDueAt);
        resolveOnCommit();
    }

    /** Frees the row so the sweep can claim it at once, without charging an attempt or rescheduling it. */
    public void releaseOnly() {
        lease.release(this);
        resolveOnCommit();
    }

    /**
     * Passes the row straight to its continuation under a new token, with a fresh budget.
     *
     * @return the continuation's message, to publish once the surrounding transaction (if any) has committed; empty
     * when this tick no longer held the row
     */
    public Optional<DiscoveryWorkMessage> handOver() {
        Optional<DiscoveryWorkMessage> continuation = lease.handOver(this);
        resolveOnCommit();
        return continuation;
    }

    public boolean resolved() {
        return resolved;
    }

    private void resolveOnCommit() {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            resolved = true;
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                resolved = true;
            }
        });
    }
}
