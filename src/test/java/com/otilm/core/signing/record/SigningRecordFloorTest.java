package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningRecordFloorTest {

    @Test
    void recordingOnWithADurableModeMeetsTheFloor() {
        // when / then
        assertThat(SigningRecordFloor.violation(true, SigningRecordPersistenceMode.DEFERRED_DURABLE)).isEmpty();
        assertThat(SigningRecordFloor.violation(true, SigningRecordPersistenceMode.IMMEDIATE)).isEmpty();
    }

    @Test
    void recordingOffViolatesTheFloor() {
        // when / then
        assertThat(SigningRecordFloor.violation(false, SigningRecordPersistenceMode.IMMEDIATE))
                .hasValueSatisfying(reason -> assertThat(reason).contains("recording is disabled"));
    }

    @Test
    void bestEffortViolatesTheFloorBecauseItIsSilentlyLossy() {
        // when / then
        assertThat(SigningRecordFloor.violation(true, SigningRecordPersistenceMode.BEST_EFFORT))
                .hasValueSatisfying(reason -> assertThat(reason).contains("BEST_EFFORT"));
    }

    @Test
    void aMissingModeViolatesTheFloor() {
        // when / then: the wording is asserted because other callers surface this reason verbatim
        assertThat(SigningRecordFloor.violation(true, null))
                .hasValueSatisfying(
                        reason -> assertThat(reason).isEqualTo("no signing-record persistence mode is set"));
    }
}
