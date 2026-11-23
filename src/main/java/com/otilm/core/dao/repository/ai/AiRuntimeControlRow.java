package com.otilm.core.dao.repository.ai;

import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AiRuntimeControlRow {
    long getGeneration();

    boolean getEnabled();

    String getImageDigest();

    Long getProfileRevision();

    Long getSecurityRevision();

    Long getTrustRevision();

    String getProtocol();

    String getCluster();

    String getNamespaceName();

    String getNamespaceUid();

    String getServiceAccountName();

    String getServiceAccountUid();

    String getTemplateDigest();

    String getRuntimeClass();

    long getObservationSequence();

    UUID getEvidenceId();

    Instant getObservedAt();

    Instant getValidUntil();

    Instant getCreatedAt();

    Instant getUpdatedAt();

    default ControlSnapshot snapshot() {
        ControlVersion version = new ControlVersion(getGeneration());
        Optional<ControlPins> pins = pins();
        Optional<ReadinessObservation> observation = Optional
                .ofNullable(getEvidenceId())
                .map(id -> new ReadinessObservation(version, pins.orElseThrow(), getObservationSequence(), id,
                        getObservedAt(), getValidUntil()));
        return new ControlSnapshot(version, getEnabled(), pins, observation, getCreatedAt(), getUpdatedAt());
    }

    default Optional<ControlPins> pins() {
        if (getImageDigest() == null) {
            return Optional.empty();
        }
        LaunchSpec launch = new LaunchSpec(getCluster(), getNamespaceName(), getNamespaceUid(), getServiceAccountName(),
                getServiceAccountUid(), getTemplateDigest(), getRuntimeClass());
        ControlPins pins = new ControlPins(getImageDigest(), getProfileRevision(), getSecurityRevision(),
                getTrustRevision(), getProtocol(), launch);
        return Optional.of(pins);
    }
}
