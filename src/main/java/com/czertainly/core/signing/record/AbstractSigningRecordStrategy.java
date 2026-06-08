package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;

/**
 * Shared skeleton for the {@link SigningRecordStrategy} implementations: the empty-policy guard and the
 * write-duration timing are identical across every persistence mode, so they live here once. Subclasses
 * implement {@link #doRecord(SigningRecordInput)} (the mode-specific persistence dispatch) and {@link #mode()}
 * (the metric tag / persistence-mode identity).
 */
public abstract class AbstractSigningRecordStrategy implements SigningRecordStrategy {

    protected final SigningRecordMetrics metrics;

    protected AbstractSigningRecordStrategy(SigningRecordMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public final void record(SigningRecordInput input) {
        if (!SigningRecordPolicy.hasAnyRecordableContent(input.getSigningProfile().recordPolicy())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        metrics.timed(mode().name(), () -> doRecord(input));
    }

    protected abstract void doRecord(SigningRecordInput input);

    protected abstract SigningRecordPersistenceMode mode();
}
