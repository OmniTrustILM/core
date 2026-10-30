package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import java.util.Optional;

/**
 * The floor a content-signing profile requires of the TIMESTAMPING profile it names as its timestamp source: recording
 * cannot be switched off, and the persistence mode must be durable. A timestamp a signature embeds must trace to a
 * record of its issuance, and {@code BEST_EFFORT} is documented as silently lossy. This is a requirement on the
 * referenced source, not on the content-signing profile's own record policy, which stays the operator's to set.
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
