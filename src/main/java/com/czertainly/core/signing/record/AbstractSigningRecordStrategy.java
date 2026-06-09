package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import lombok.extern.slf4j.Slf4j;

/**
 * Shared skeleton for the {@link SigningRecordStrategy} implementations: the recording-disabled guard and the
 * write-duration timing are identical across every persistence mode, so they live here once. Subclasses
 * implement {@link #doRecord(SigningRecordInput)} (the mode-specific persistence dispatch) and {@link #mode()}
 * (the metric tag / persistence-mode identity).
 *
 * <p>{@code recordingEnabled} is the sole gate on whether a record is written: when it is on, every signing
 * operation produces a record carrying at least its intrinsic metadata (who, when, which profile/version),
 * with the per-field {@code record*} content toggles deciding only which optional payload columns are filled.</p>
 */
@Slf4j
public abstract class AbstractSigningRecordStrategy implements SigningRecordStrategy {

    protected final SigningRecordMetrics metrics;

    protected AbstractSigningRecordStrategy(SigningRecordMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public final void recordSigning(SigningRecordInput input) {
        metrics.intake(mode().name()).increment();
        if (!input.getSigningProfile().recordPolicy().recordingEnabled()) {
            log.debug("Signing Record creation is disabled for signing profile {}; skipping the {} record.",
                    input.getSigningProfile().uuid(), mode().name());
            metrics.intakeSkipped(mode().name()).increment();
            return;
        }
        metrics.timed(mode().name(), () -> doRecord(input));
    }

    protected abstract void doRecord(SigningRecordInput input);

    protected abstract SigningRecordPersistenceMode mode();
}
