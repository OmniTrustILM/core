package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.util.AiRuntimeFixture;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeControlStateTest {
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private final ControlVersion version = new ControlVersion(2);
    private final ControlPins pins = ControlPins.forAttempt(AiRuntimeFixture.attempt(NOW));

    @Test
    void configuredOrEnabledFlagsAloneAreNotReadiness() {
        ControlSnapshot initial = snapshot(false, Optional.empty(), Optional.empty());
        ControlSnapshot configured = snapshot(true, Optional.of(pins), Optional.empty());

        assertThat(initial.freshAt(NOW)).isFalse();
        assertThat(initial.usableAt(NOW)).isFalse();
        assertThat(configured.freshAt(NOW)).isFalse();
        assertThat(configured.usableAt(NOW)).isFalse();
    }

    @Test
    void freshEvidenceRequiresSeparateEnableAndDeniesBothTimeEdges() {
        ReadinessObservation observation = observation(NOW, NOW.plusSeconds(10));
        ControlSnapshot disabled = snapshot(false, Optional.of(pins), Optional.of(observation));
        ControlSnapshot enabled = snapshot(true, Optional.of(pins), Optional.of(observation));

        assertThat(disabled.freshAt(NOW)).isTrue();
        assertThat(disabled.usableAt(NOW)).isFalse();
        assertThat(enabled.usableAt(NOW)).isTrue();
        assertThat(enabled.usableAt(NOW.minusNanos(1))).isFalse();
        assertThat(enabled.usableAt(NOW.plusSeconds(10))).isFalse();
    }

    @Test
    void databasePrecisionCanOnlyNarrowAnObservationWindow() {
        Instant start = Instant.parse("2026-11-04T12:00:00.123456001Z");
        Instant end = Instant.parse("2026-11-04T12:00:01.123456999Z");
        ReadinessObservation observation = observation(start, end);

        assertThat(observation.observedAt()).isEqualTo(Instant.parse("2026-11-04T12:00:00.123457Z"));
        assertThat(observation.validUntil()).isEqualTo(Instant.parse("2026-11-04T12:00:01.123456Z"));
        assertThat(observation.observedAt()).isAfter(start);
        assertThat(observation.validUntil()).isBefore(end);
    }

    @Test
    void versionsSequencesAndEmptyWindowsAreRejectedWithoutInputEcho() {
        assertThatThrownBy(() -> new ControlVersion(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ControlVersion(-1)).isInstanceOf(IllegalArgumentException.class);
        UUID evidenceId = UUID.randomUUID();
        Instant expiry = NOW.plusSeconds(1);
        assertThatThrownBy(() -> new ReadinessObservation(version, pins, 0, evidenceId, NOW, expiry))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ReadinessObservation(version, pins, 1, evidenceId, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
        Instant subMicrosecondEnd = NOW.plusNanos(500);
        assertThatThrownBy(() -> new ReadinessObservation(version, pins, 1, evidenceId, NOW, subMicrosecondEnd))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void evidenceCannotBeAttachedToAnotherGenerationOrPins() {
        ReadinessObservation observation = observation(NOW, NOW.plusSeconds(10));
        Optional<ControlPins> currentPins = Optional.of(pins);
        Optional<ReadinessObservation> evidence = Optional.of(observation);
        ControlVersion different = new ControlVersion(3);

        assertThatThrownBy(() -> new ControlSnapshot(different, false, currentPins, evidence, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ControlSnapshot(version, false, Optional.empty(), evidence, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ControlSnapshot(version, true, Optional.empty(), Optional.empty(), NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private ReadinessObservation observation(Instant start, Instant end) {
        return new ReadinessObservation(version, pins, 1, UUID.randomUUID(), start, end);
    }

    private ControlSnapshot snapshot(boolean enabled, Optional<ControlPins> controlPins,
            Optional<ReadinessObservation> observation) {
        return new ControlSnapshot(version, enabled, controlPins, observation, NOW, NOW);
    }
}
