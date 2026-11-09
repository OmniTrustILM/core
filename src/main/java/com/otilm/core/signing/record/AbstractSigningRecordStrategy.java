package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.model.signing.SigningProfileModel;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

/**
 * Shared skeleton for the {@link SigningRecordStrategy} implementations: the recording-disabled guard and the
 * write-duration timing are identical across every persistence mode, so they live here once. Subclasses implement
 * {@link #doRecord(List)} (the mode-specific persistence dispatch) and {@link #mode()} (the metric tag /
 * persistence-mode identity).
 *
 * <p>
 * {@code recordingEnabled} is the sole gate on whether a record is written: when it is on, every signing operation
 * produces a record carrying at least its intrinsic metadata (who, when, which profile/version), with the per-field
 * {@code record*} content toggles deciding only which optional payload columns are filled.
 * </p>
 */
@Slf4j
public abstract class AbstractSigningRecordStrategy implements SigningRecordStrategy {

    protected final SigningRecordMetrics metrics;

    protected AbstractSigningRecordStrategy(SigningRecordMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public final List<UUID> record(SigningProfileModel<?, ?> signingProfile, List<SigningRecordInputSource> sources) {
        if (sources.isEmpty()) {
            return List.of();
        }
        requireBatchProfile(signingProfile, sources);
        if (!admitIntake(signingProfile, sources.size())) {
            return List.of();
        }
        List<SigningRecordInput> inputs = sources.stream().map(SigningRecordInputSource::build).toList();
        return metrics.timed(mode().name(), inputs.size(), () -> doRecord(inputs));
    }

    /** The batch's profile gates every record of the batch. A source carrying another profile is refused. */
    private static void requireBatchProfile(SigningProfileModel<?, ?> signingProfile,
            List<SigningRecordInputSource> sources) {
        if (sources.stream().anyMatch(source -> !signingProfile.equals(source.signingProfile()))) {
            throw new IllegalArgumentException(
                    "every source of a batch must carry the batch's signing profile " + signingProfile.uuid());
        }
    }

    private boolean admitIntake(SigningProfileModel<?, ?> signingProfile, int operations) {
        metrics.intake(mode().name()).increment(operations);
        if (signingProfile.recordPolicy().recordingEnabled()) {
            return true;
        }
        log
                .debug("Signing Record creation is disabled for signing profile {}; skipping {} {} record(s).",
                        signingProfile.uuid(), operations, mode().name());
        metrics.intakeSkipped(mode().name()).increment(operations);
        return false;
    }

    /** Hands the records of one batch to the mode's persistence. Returns their UUIDs in input order. */
    protected abstract List<UUID> doRecord(List<SigningRecordInput> inputs);

    protected abstract SigningRecordPersistenceMode mode();
}
