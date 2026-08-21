package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import java.util.Optional;

/**
 * The AdES record floor: recording cannot be switched off, and the persistence mode must be durable. A signature that
 * leaves no record cannot be traced back to what authorized it, and {@code BEST_EFFORT} is documented as silently
 * lossy.
 */
public final class SigningRecordFloor {

    private SigningRecordFloor() {
    }

    /**
     * @return the reason the floor is not met, or empty when it is
     */
    public static Optional<String> violation(boolean recordingEnabled, SigningRecordPersistenceMode mode) {
        if (!recordingEnabled) {
            return Optional.of("recording is disabled");
        }
        if (mode == null) {
            return Optional.of("no signing-record persistence mode is set");
        }
        return switch (mode) {
            case IMMEDIATE, DEFERRED_DURABLE -> Optional.empty();
            case BEST_EFFORT -> Optional
                    .of("signing-record persistence mode is BEST_EFFORT, which is silently lossy; DEFERRED_DURABLE is the minimum");
        };
    }
}
