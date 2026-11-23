package com.otilm.core.model.ai;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/** Local persisted facts; constructing them grants no workload identity or authorization. */
public final class AiRuntimeState {
    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");

    private AiRuntimeState() {
    }

    public enum RunState {
        QUEUED,
        RUNNING,
        FAILED,
        CANCELLED,
        LIMIT_REACHED
    }

    public enum AttemptState {
        LAUNCHING,
        CLAIMED,
        FENCED
    }

    public enum CleanupState {
        NONE,
        DUE,
        DONE
    }

    public enum WorkloadState {
        ELIGIBLE,
        REGISTERED,
        CLOSED
    }

    public enum FailureReason {
        LAUNCH_EXPIRED,
        LEASE_EXPIRED,
        PENDING_EXHAUSTED,
        OBSERVATION_EXPIRED,
        JOB_CONFLICT,
        CANCELLED,
        INVALIDATED
    }

    public enum Status {
        APPLIED,
        REPLAY,
        PENDING,
        LOSER,
        STALE,
        EXPIRED,
        CANCELLED,
        CONFLICT,
        LIMIT_REACHED,
        DENIED
    }

    public record ControlVersion(long generation) {
        public ControlVersion {
            positive(generation);
        }
    }

    public record ControlPins(String imageDigest, long profileRevision, long securityRevision, long trustRevision,
            String protocol, LaunchSpec launch) {
        public ControlPins {
            digest(imageDigest);
            positive(profileRevision);
            positive(securityRevision);
            positive(trustRevision);
            supportedProtocol(protocol);
            Objects.requireNonNull(launch);
        }

        public static ControlPins forAttempt(AttemptSpec attempt) {
            return new ControlPins(attempt.imageDigest(), attempt.profileRevision(), attempt.securityRevision(),
                    attempt.trustRevision(), attempt.protocol(), attempt.launch());
        }
    }

    /** Stored local observation facts; only a separately qualified trusted producer may assert readiness. */
    public record ReadinessObservation(ControlVersion expected, ControlPins observedPins, long sequence,
            UUID evidenceId, Instant observedAt, Instant validUntil) {
        public ReadinessObservation {
            Objects.requireNonNull(expected);
            Objects.requireNonNull(observedPins);
            positive(sequence);
            Objects.requireNonNull(evidenceId);
            Objects.requireNonNull(observedAt);
            Objects.requireNonNull(validUntil);
            Instant truncated = observedAt.truncatedTo(ChronoUnit.MICROS);
            observedAt = truncated.equals(observedAt) ? truncated : truncated.plus(1, ChronoUnit.MICROS);
            validUntil = validUntil.truncatedTo(ChronoUnit.MICROS);
            if (!observedAt.isBefore(validUntil)) {
                throw new IllegalArgumentException("Invalid runtime readiness window");
            }
        }
    }

    public record ControlSnapshot(ControlVersion version, boolean enabled, Optional<ControlPins> pins,
            Optional<ReadinessObservation> observation, Instant createdAt, Instant updatedAt) {
        public ControlSnapshot {
            Objects.requireNonNull(version);
            Objects.requireNonNull(pins);
            Objects.requireNonNull(observation);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(updatedAt);
            if (enabled && pins.isEmpty() || observation
                    .filter(value -> !value.expected().equals(version) || pins.isEmpty()
                            || !value.observedPins().equals(pins.orElseThrow()))
                    .isPresent()) {
                throw new IllegalArgumentException("Invalid runtime control snapshot");
            }
        }

        public boolean freshAt(Instant at) {
            return observation
                    .filter(value -> !value.observedAt().isAfter(at) && value.validUntil().isAfter(at))
                    .isPresent();
        }

        public boolean usableAt(Instant at) {
            return enabled && freshAt(at);
        }
    }

    public record Expected(UUID runId, UUID attemptId, long runRevision, long fence) {
        public Expected {
            Objects.requireNonNull(runId);
            Objects.requireNonNull(attemptId);
            positive(runRevision);
            positive(fence);
        }
    }

    public record Transition<T>(Status status, Optional<T> value) {
        public Transition {
            Objects.requireNonNull(status);
            Objects.requireNonNull(value);
            if (value.isPresent() && status != Status.APPLIED && status != Status.REPLAY) {
                throw new IllegalArgumentException("Rejected runtime transitions cannot return protected values");
            }
        }

        public static <T> Transition<T> empty(Status status) {
            return new Transition<>(status, Optional.empty());
        }

        public static <T> Transition<T> value(Status status, T value) {
            return new Transition<>(status, Optional.of(value));
        }
    }

    public record WorkloadObservation(Expected expected, String cluster, String namespaceName, String namespaceUid,
            String serviceAccountName, String serviceAccountUid, String jobName, String jobUid, String podName,
            String podUid, String imageDigest, String templateDigest, String runtimeClass, long profileRevision,
            long securityRevision, long trustRevision, String protocol, long sequence, Instant validUntil,
            boolean registered) {
        public WorkloadObservation {
            Objects.requireNonNull(expected);
            text(cluster, 128);
            text(namespaceName, 63);
            text(namespaceUid, 128);
            text(serviceAccountName, 253);
            text(serviceAccountUid, 128);
            text(jobName, 63);
            text(jobUid, 128);
            text(podName, 253);
            text(podUid, 128);
            digest(imageDigest);
            digest(templateDigest);
            text(runtimeClass, 253);
            positive(profileRevision);
            positive(securityRevision);
            positive(trustRevision);
            supportedProtocol(protocol);
            positive(sequence);
            Objects.requireNonNull(validUntil);
        }
    }

    public record RunSpec(UUID runId, Optional<UUID> conversationRef, UUID actorId, String scopeMarker,
            int attemptLimit, int podLimit, int leaseSeconds, Instant runDeadline) {
        public RunSpec {
            Objects.requireNonNull(runId);
            Objects.requireNonNull(conversationRef);
            Objects.requireNonNull(actorId);
            text(scopeMarker, 64);
            range(attemptLimit, 1, 10);
            range(podLimit, 2, 16);
            range(leaseSeconds, 1, 60);
            Objects.requireNonNull(runDeadline);
        }
    }

    public record LaunchSpec(String cluster, String namespaceName, String namespaceUid, String serviceAccountName,
            String serviceAccountUid, String templateDigest, String runtimeClass) {
        public LaunchSpec {
            text(cluster, 128);
            text(namespaceName, 63);
            text(namespaceUid, 128);
            text(serviceAccountName, 253);
            text(serviceAccountUid, 128);
            digest(templateDigest);
            text(runtimeClass, 253);
        }
    }

    public record AttemptSpec(UUID attemptId, Instant launchDeadline, Instant maxDeadline, String imageDigest,
            long profileRevision, long securityRevision, long trustRevision, String protocol, LaunchSpec launch) {
        public AttemptSpec {
            Objects.requireNonNull(attemptId);
            Objects.requireNonNull(launchDeadline);
            Objects.requireNonNull(maxDeadline);
            if (launchDeadline.isAfter(maxDeadline)) {
                throw new IllegalArgumentException("Runtime launch deadline exceeds the attempt deadline");
            }
            digest(imageDigest);
            positive(profileRevision);
            positive(securityRevision);
            positive(trustRevision);
            supportedProtocol(protocol);
            Objects.requireNonNull(launch);
        }
    }

    public record WorkloadRef(String cluster, String podUid) {
        public WorkloadRef {
            text(cluster, 128);
            text(podUid, 128);
        }
    }

    public record ClaimBinding(UUID runId, UUID attemptId, WorkloadRef workload, UUID claimId, long fence) {
        public ClaimBinding {
            Objects.requireNonNull(runId);
            Objects.requireNonNull(attemptId);
            Objects.requireNonNull(workload);
            Objects.requireNonNull(claimId);
            positive(fence);
        }
    }

    public record Claim(ClaimBinding binding, Instant leaseUntil, long heartbeatSequence) {
        public Claim {
            Objects.requireNonNull(binding);
            Objects.requireNonNull(leaseUntil);
            if (heartbeatSequence < 0) {
                throw new IllegalArgumentException("Invalid runtime heartbeat sequence");
            }
        }
    }

    public record AttemptSnapshot(AttemptSpec spec, int attemptNo, AttemptState state, long fence,
            Optional<FailureReason> failure, Optional<Claim> claim, long controlGeneration, Instant createdAt,
            Instant updatedAt) {
        public AttemptSnapshot {
            Objects.requireNonNull(spec);
            Objects.requireNonNull(state);
            Objects.requireNonNull(failure);
            Objects.requireNonNull(claim);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(updatedAt);
            nonnegativeGeneration(controlGeneration);
        }
    }

    public record LaunchSnapshot(LaunchSpec spec, String jobName, Optional<String> jobUid, long observationSequence,
            CleanupState cleanup, Instant createdAt, Instant updatedAt) {
        public LaunchSnapshot {
            Objects.requireNonNull(spec);
            Objects.requireNonNull(jobName);
            Objects.requireNonNull(jobUid);
            Objects.requireNonNull(cleanup);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(updatedAt);
        }
    }

    public record WorkloadSnapshot(WorkloadRef ref, String podName, String jobUid, WorkloadState state,
            long observationSequence, Instant observationValidUntil, Optional<Instant> firstPendingAt,
            Optional<Instant> pendingDeadline, int pendingReturns, Optional<Instant> bootstrapConsumedAt,
            Instant createdAt, Instant updatedAt) {
        public WorkloadSnapshot {
            Objects.requireNonNull(ref);
            Objects.requireNonNull(podName);
            Objects.requireNonNull(jobUid);
            Objects.requireNonNull(state);
            Objects.requireNonNull(observationValidUntil);
            Objects.requireNonNull(firstPendingAt);
            Objects.requireNonNull(pendingDeadline);
            Objects.requireNonNull(bootstrapConsumedAt);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(updatedAt);
        }
    }

    public record RunSnapshot(RunSpec spec, RunState state, long revision, long fence, int attemptsUsed,
            AttemptSnapshot attempt, LaunchSnapshot launch, List<WorkloadSnapshot> workloads, long controlGeneration,
            Instant createdAt, Instant updatedAt) {
        public RunSnapshot {
            Objects.requireNonNull(spec);
            Objects.requireNonNull(state);
            Objects.requireNonNull(attempt);
            Objects.requireNonNull(launch);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(updatedAt);
            workloads = List.copyOf(workloads);
            nonnegativeGeneration(controlGeneration);
            if (attempt.controlGeneration() != controlGeneration) {
                throw new IllegalArgumentException("Runtime control generation mismatch");
            }
        }
    }

    private static void supportedProtocol(String protocol) {
        if (!"v1".equals(protocol)) {
            throw new IllegalArgumentException("Unsupported runtime protocol");
        }
    }

    private static void nonnegativeGeneration(long generation) {
        if (generation < 0) {
            throw new IllegalArgumentException("Invalid runtime control generation");
        }
    }

    private static void range(int value, int minimum, int maximum) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException("Runtime bound outside supported range");
        }
    }

    private static void positive(long value) {
        if (value < 1) {
            throw new IllegalArgumentException("Runtime revision must be positive");
        }
    }

    private static void text(String value, int maximum) {
        Objects.requireNonNull(value);
        if (value.isBlank() || value.length() > maximum) {
            throw new IllegalArgumentException("Invalid runtime identifier length");
        }
    }

    private static void digest(String value) {
        Objects.requireNonNull(value);
        if (!DIGEST.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid runtime image or template digest");
        }
    }
}
