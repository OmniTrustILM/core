package com.otilm.core.service.writer.ai;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.FailureReason;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@TraceMetadataOnly
public class AiRuntimeWriter {
    private final AiRuntimeRepository repository;
    private final AiRuntimeDatabaseCalls database;

    public AiRuntimeWriter(AiRuntimeRepository repository) {
        this.repository = repository;
        this.database = new AiRuntimeDatabaseCalls(repository);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<RunSnapshot> snapshot(UUID runId, AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> repository.snapshot(runId));
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<ControlSnapshot> control(AiRuntimeOperationBudget budget) {
        return database.query(budget, repository::control);
    }

    @Transactional(timeout = 5)
    public Transition<Void> observe(WorkloadObservation observation, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        return observe(observation, Optional.of(budget));
    }

    @Transactional(timeout = 5)
    public Transition<Void> invalidate(Expected expected, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        return invalidate(expected, Optional.of(budget));
    }

    @Transactional(timeout = 5)
    public Transition<ControlSnapshot> changeControl(ControlVersion expected, ControlPins pins) {
        return withControl(expected, locked -> {
            if (expected.generation() == Long.MAX_VALUE) {
                return Transition.empty(Status.LIMIT_REACHED);
            }
            applied(repository.changeControl(expected, pins, locked.at()));
            return Transition.value(Status.APPLIED, repository.control().orElseThrow());
        });
    }

    @Transactional(timeout = 5)
    public Transition<Void> disableControl(ControlVersion expected) {
        return withControl(expected, locked -> {
            applied(repository.disableControl(expected, locked.at()));
            return Transition.empty(Status.APPLIED);
        });
    }

    @Transactional(timeout = 5)
    public Transition<Void> enableControl(ControlVersion expected) {
        return withControl(expected, locked -> {
            Status freshness = evidenceStatus(locked.control(), locked.at());
            if (freshness != Status.APPLIED) {
                return Transition.empty(freshness);
            }
            if (expected.generation() == Long.MAX_VALUE) {
                return Transition.empty(Status.LIMIT_REACHED);
            }
            if (locked.control().enabled()) {
                return Transition
                        .empty(repository.controlUsable(expected.generation()) ? Status.REPLAY : Status.EXPIRED);
            }
            applied(repository.enableControl(expected, locked.at()));
            return Transition.empty(Status.APPLIED);
        });
    }

    @Transactional(timeout = 5)
    public Transition<Void> observeControl(ReadinessObservation observation) {
        return withControl(observation.expected(), locked -> {
            Status status = readinessStatus(locked, observation);
            if (status != Status.APPLIED) {
                return Transition.empty(status);
            }
            applied(repository.observeControl(observation, locked.at()));
            return Transition.empty(Status.APPLIED);
        });
    }

    @Transactional(timeout = 5)
    public RunSnapshot create(ControlVersion expectedControl, RunSpec run, AttemptSpec attempt) {
        repository.configureTransaction();
        Optional<ControlSnapshot> control = lockedControl();
        Instant at = repository.decisionTime();
        if (control.isEmpty() || !control.orElseThrow().version().equals(expectedControl)
                || !control.orElseThrow().usableAt(at)
                || control
                        .orElseThrow()
                        .pins()
                        .filter(pins -> pins.equals(ControlPins.forAttempt(attempt)))
                        .isEmpty()) {
            throw new Rejected();
        }
        if (!run.runDeadline().isAfter(at) || !attempt.launchDeadline().isAfter(at)
                || attempt.maxDeadline().isAfter(run.runDeadline())) {
            throw new IllegalStateException("Runtime deadlines do not permit creation");
        }
        applied(repository.create(expectedControl, run, attempt));
        return repository
                .snapshot(run.runId())
                .orElseThrow(() -> new IllegalStateException("Runtime creation did not persist its snapshot"));
    }

    @Transactional(timeout = 5)
    public Transition<Void> observe(WorkloadObservation observation) {
        return observe(observation, Optional.empty());
    }

    private Transition<Void> observe(WorkloadObservation observation, Optional<AiRuntimeOperationBudget> budget) {
        Optional<Locked> loaded = lockAdmission(observation.expected().runId(), budget);
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        Status status = checkedAdmission(locked, observation.expected());
        if (status != Status.APPLIED) {
            return Transition.empty(status);
        }
        RunSnapshot run = locked.run();
        if (!pinsMatch(run, observation) || !observation.validUntil().isAfter(locked.at())
                || observation.validUntil().isAfter(run.attempt().spec().maxDeadline())) {
            return Transition.empty(Status.DENIED);
        }
        if (run.launch().jobUid().filter(uid -> !uid.equals(observation.jobUid())).isPresent()) {
            if (run.attempt().state() == AttemptState.LAUNCHING) {
                fence(locked, FailureReason.JOB_CONFLICT, RunState.FAILED, budget);
            }
            return Transition.empty(Status.CONFLICT);
        }
        WorkloadRef ref = new WorkloadRef(observation.cluster(), observation.podUid());
        Optional<WorkloadSnapshot> existing = workload(run, ref);
        Status observed = observationStatus(existing, observation);
        if (observed != Status.APPLIED) {
            return Transition
                    .empty(observed == Status.REPLAY && !query(budget, () -> repository.admissionCurrent(expected(run)))
                            ? Status.EXPIRED
                            : observed);
        }
        Optional<UUID> owner = query(budget, () -> repository.workloadAttempt(ref.cluster(), ref.podUid()));
        if (owner.filter(id -> !id.equals(run.attempt().spec().attemptId())).isPresent()) {
            return Transition.empty(Status.DENIED);
        }
        if (existing.isEmpty()
                && query(budget, () -> repository.outstandingWorkloads(run.spec().runId())) >= run.spec().podLimit()) {
            return Transition.empty(Status.LIMIT_REACHED);
        }
        applied(query(budget, () -> repository.observe(observation, locked.at())));
        return Transition.empty(Status.APPLIED);
    }

    @Transactional(timeout = 5)
    public Transition<Claim> bootstrap(Expected expected, WorkloadRef ref) {
        return bootstrap(expected, ref, Optional.empty());
    }

    private Transition<Claim> bootstrap(Expected expected, WorkloadRef ref, Optional<AiRuntimeOperationBudget> budget) {
        Optional<Locked> loaded = lockAdmission(expected.runId(), budget);
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        Optional<Instant> operationDeadline = budget.map(value -> value.databaseCutoff(locked.at()));
        Status status = checkedAdmission(locked, expected);
        if (status != Status.APPLIED) {
            return Transition.empty(status);
        }
        RunSnapshot run = locked.run();
        if (run.attempt().claim().isPresent()) {
            Claim claim = run.attempt().claim().orElseThrow();
            if (!admissionCurrent(expected(run), operationDeadline, budget)) {
                return Transition.empty(Status.EXPIRED);
            }
            return claim.binding().workload().equals(ref)
                    ? Transition.value(Status.REPLAY, claim)
                    : Transition.empty(Status.LOSER);
        }
        Optional<WorkloadSnapshot> found = workload(run, ref);
        if (found.isEmpty() || !found.orElseThrow().observationValidUntil().isAfter(locked.at())) {
            return Transition.empty(Status.DENIED);
        }
        WorkloadSnapshot row = found.orElseThrow();
        if (row.pendingDeadline().filter(deadline -> !deadline.isAfter(locked.at())).isPresent()) {
            return exhaustedPending(locked, budget);
        }
        if (row.state() == WorkloadState.ELIGIBLE) {
            return pending(locked, row, operationDeadline, budget);
        }
        if (row.state() != WorkloadState.REGISTERED || row.bootstrapConsumedAt().isPresent()) {
            return Transition.empty(Status.DENIED);
        }
        UUID claimId = UUID.randomUUID();
        Instant until = leaseUntil(locked);
        int affected = query(budget, () -> operationDeadline.isPresent()
                ? repository.claimBefore(expected, ref, claimId, until, locked.at(), operationDeadline.orElseThrow())
                : repository.claim(expected, ref, claimId, until, locked.at()));
        applied(affected);
        return Transition.value(Status.APPLIED, snapshot(run.spec().runId(), budget).attempt().claim().orElseThrow());
    }

    @Transactional(timeout = 5)
    public Transition<Claim> heartbeat(ClaimBinding binding, long sequence) {
        return heartbeat(binding, sequence, Optional.empty());
    }

    private Transition<Claim> heartbeat(ClaimBinding binding, long sequence,
            Optional<AiRuntimeOperationBudget> budget) {
        if (sequence <= 0) {
            return Transition.empty(Status.DENIED);
        }
        Optional<Locked> loaded = lockAdmission(binding.runId(), budget);
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        Optional<Instant> operationDeadline = budget.map(value -> value.databaseCutoff(locked.at()));
        Status authority = admissionStatus(locked);
        if (authority != Status.APPLIED) {
            return Transition.empty(authority);
        }
        Status terminal = terminalStatus(locked.run());
        if (terminal != Status.APPLIED) {
            return Transition.empty(terminal);
        }
        Optional<Claim> stored = locked.run().attempt().claim();
        if (stored.isEmpty() || !stored.orElseThrow().binding().equals(binding)
                || binding.fence() != locked.run().fence()) {
            return Transition.empty(Status.STALE);
        }
        Status status = liveStatus(locked);
        if (status != Status.APPLIED) {
            return Transition.empty(status);
        }
        Claim claim = stored.orElseThrow();
        if (sequence < claim.heartbeatSequence()) {
            return Transition.empty(Status.STALE);
        }
        if (sequence == claim.heartbeatSequence()) {
            return admissionCurrent(expected(locked.run()), operationDeadline, budget)
                    ? Transition.value(Status.REPLAY, claim)
                    : Transition.empty(Status.EXPIRED);
        }
        Instant until = leaseUntil(locked);
        int affected = query(budget,
                () -> operationDeadline.isPresent()
                        ? repository
                                .heartbeatBefore(expected(locked.run()), binding, sequence, until, locked.at(),
                                        operationDeadline.orElseThrow())
                        : repository.heartbeat(expected(locked.run()), binding, sequence, until, locked.at()));
        applied(affected);
        return Transition.value(Status.APPLIED, snapshot(binding.runId(), budget).attempt().claim().orElseThrow());
    }

    @Transactional(timeout = 5)
    public Transition<Claim> bootstrap(Expected expected, WorkloadRef workload, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        return bootstrap(expected, workload, Optional.of(budget));
    }

    @Transactional(timeout = 5)
    public Transition<Claim> heartbeat(ClaimBinding claim, long sequence, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        return heartbeat(claim, sequence, Optional.of(budget));
    }

    @Transactional(timeout = 5)
    public Transition<Void> cancel(UUID runId) {
        Optional<Locked> loaded = lock(runId);
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        if (locked.run().state() == RunState.CANCELLED) {
            return Transition.empty(Status.REPLAY);
        }
        if (terminalStatus(locked.run()) != Status.APPLIED) {
            return Transition.empty(Status.DENIED);
        }
        if (locked.run().attempt().state() == AttemptState.FENCED) {
            applied(repository.terminateFenced(expected(locked.run()), RunState.CANCELLED, locked.at()));
        } else {
            fence(locked, FailureReason.CANCELLED, RunState.CANCELLED);
        }
        return Transition.empty(Status.APPLIED);
    }

    @Transactional(timeout = 5)
    public Transition<Void> invalidate(Expected expected) {
        return invalidate(expected, Optional.empty());
    }

    private Transition<Void> invalidate(Expected expected, Optional<AiRuntimeOperationBudget> budget) {
        Optional<Locked> loaded = lock(expected.runId(), budget);
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        if (!expected(locked.run()).equals(expected)) {
            return Transition.empty(Status.STALE);
        }
        if (terminalStatus(locked.run()) != Status.APPLIED) {
            return Transition.empty(Status.DENIED);
        }
        if (locked.run().attempt().state() == AttemptState.FENCED) {
            applied(query(budget, () -> repository.terminateFenced(expected, RunState.FAILED, locked.at())));
        } else {
            fence(locked, FailureReason.INVALIDATED, RunState.FAILED, budget);
        }
        return Transition.empty(Status.APPLIED);
    }

    @Transactional(timeout = 5)
    public Transition<Void> expire(Expected expected) {
        Optional<Locked> loaded = lock(expected.runId());
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        if (!expected(locked.run()).equals(expected)) {
            return Transition.empty(Status.STALE);
        }
        if (terminalStatus(locked.run()) != Status.APPLIED) {
            return Transition.empty(Status.DENIED);
        }
        if (locked.run().attempt().state() == AttemptState.FENCED) {
            if (recoverableState(locked) != RunState.LIMIT_REACHED) {
                return Transition.empty(Status.DENIED);
            }
            applied(repository.terminateFenced(expected, RunState.LIMIT_REACHED, locked.at()));
            return Transition.empty(Status.APPLIED);
        }
        Optional<FailureReason> reason = expiryReason(locked);
        if (reason.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        fence(locked, reason.orElseThrow(), recoverableState(locked));
        return Transition.empty(Status.APPLIED);
    }

    @Transactional(timeout = 5)
    public Transition<RunSnapshot> replace(Expected expected, AttemptSpec next) {
        Optional<Locked> loaded = lockAdmission(expected.runId());
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Locked locked = loaded.orElseThrow();
        RunSnapshot run = locked.run();
        Status authority = admissionStatus(locked);
        if (authority != Status.APPLIED) {
            return Transition.empty(authority);
        }
        if (!expected(run).equals(expected)) {
            return Transition.empty(Status.STALE);
        }
        Status terminal = terminalStatus(run);
        if (terminal != Status.APPLIED) {
            return Transition.empty(terminal);
        }
        if (run.state() != RunState.QUEUED || run.attempt().state() != AttemptState.FENCED
                || run.attempt().failure().filter(AiRuntimeWriter::recoverable).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        if (recoverableState(locked) == RunState.LIMIT_REACHED) {
            applied(repository.terminateFenced(expected, RunState.LIMIT_REACHED, locked.at()));
            return Transition.empty(Status.LIMIT_REACHED);
        }
        if (repository.outstandingWorkloads(run.spec().runId()) >= run.spec().podLimit()) {
            return Transition.empty(Status.LIMIT_REACHED);
        }
        if (!replacementPinsMatch(run.attempt().spec(), next) || !next.launchDeadline().isAfter(locked.at())
                || next.maxDeadline().isAfter(run.spec().runDeadline())) {
            return Transition.empty(Status.CONFLICT);
        }
        applied(repository.replace(expected, next, locked.at()));
        return Transition.value(Status.APPLIED, snapshot(run.spec().runId()));
    }

    private Transition<Claim> pending(Locked locked, WorkloadSnapshot row, Optional<Instant> operationDeadline,
            Optional<AiRuntimeOperationBudget> budget) {
        if (row.pendingReturns() >= 11) {
            return exhaustedPending(locked, budget);
        }
        Instant deadline = row
                .pendingDeadline()
                .orElseGet(() -> earlier(locked.at().plusSeconds(30), locked.run().attempt().spec().launchDeadline()));
        int affected = query(budget,
                () -> operationDeadline.isPresent()
                        ? repository
                                .pendingBefore(expected(locked.run()), row.ref(), deadline, locked.at(),
                                        operationDeadline.orElseThrow())
                        : repository.pending(expected(locked.run()), row.ref(), deadline, locked.at()));
        applied(affected);
        return Transition.empty(Status.PENDING);
    }

    private Transition<Claim> exhaustedPending(Locked locked, Optional<AiRuntimeOperationBudget> budget) {
        fence(locked, FailureReason.PENDING_EXHAUSTED, recoverableState(locked), budget);
        return Transition.empty(Status.EXPIRED);
    }

    private Optional<Locked> lock(UUID runId) {
        return lock(runId, Optional.empty());
    }

    private Optional<Locked> lock(UUID runId, Optional<AiRuntimeOperationBudget> budget) {
        if (budget.isEmpty()) {
            repository.configureTransaction();
        }
        return lockRun(runId, Optional.empty(), budget);
    }

    private Optional<Locked> lockAdmission(UUID runId) {
        return lockAdmission(runId, Optional.empty());
    }

    private Optional<Locked> lockAdmission(UUID runId, Optional<AiRuntimeOperationBudget> budget) {
        if (budget.isEmpty()) {
            repository.configureTransaction();
        }
        Optional<ControlSnapshot> control = lockedControl(budget);
        return lockRun(runId, control, budget);
    }

    private Optional<Locked> lockRun(UUID runId, Optional<ControlSnapshot> control,
            Optional<AiRuntimeOperationBudget> budget) {
        if (query(budget, () -> repository.lockRun(runId)).isEmpty()) {
            return Optional.empty();
        }
        RunSnapshot run = snapshot(runId, budget);
        UUID attemptId = run.attempt().spec().attemptId();
        query(budget, () -> repository.lockAttempt(attemptId));
        query(budget, () -> repository.lockLaunch(attemptId));
        query(budget, () -> repository.lockWorkloads(attemptId));
        return Optional.of(new Locked(snapshot(runId, budget), query(budget, repository::decisionTime), control));
    }

    private Optional<ControlSnapshot> lockedControl() {
        return lockedControl(Optional.empty());
    }

    private Optional<ControlSnapshot> lockedControl(Optional<AiRuntimeOperationBudget> budget) {
        return query(budget, repository::lockControl).isEmpty() ? Optional.empty() : query(budget, repository::control);
    }

    private <T> Transition<T> withControl(ControlVersion expected, Function<LockedControl, Transition<T>> action) {
        repository.configureTransaction();
        Optional<ControlSnapshot> loaded = lockedControl();
        if (loaded.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        ControlSnapshot control = loaded.orElseThrow();
        if (!control.version().equals(expected)) {
            return Transition.empty(Status.STALE);
        }
        return action.apply(new LockedControl(control, repository.decisionTime()));
    }

    private Status readinessStatus(LockedControl locked, ReadinessObservation observation) {
        ControlSnapshot control = locked.control();
        if (control.pins().filter(observation.observedPins()::equals).isEmpty()
                || observation.observedAt().isAfter(locked.at())) {
            return Status.DENIED;
        }
        if (!observation.validUntil().isAfter(locked.at())) {
            return Status.EXPIRED;
        }
        if (control.observation().isEmpty()) {
            return control.enabled() ? Status.DENIED : Status.APPLIED;
        }
        Status freshness = evidenceStatus(control, locked.at());
        if (freshness != Status.APPLIED) {
            return freshness;
        }
        ReadinessObservation stored = control.observation().orElseThrow();
        if (observation.sequence() == stored.sequence()) {
            if (!observation.equals(stored)) {
                return Status.CONFLICT;
            }
            return repository.controlEvidenceCurrent(control.version().generation(), stored.sequence())
                    ? Status.REPLAY
                    : Status.EXPIRED;
        }
        return observation.sequence() < stored.sequence() || observation.observedAt().isBefore(stored.observedAt())
                ? Status.STALE
                : Status.APPLIED;
    }

    private static Status evidenceStatus(ControlSnapshot control, Instant at) {
        if (control.freshAt(at)) {
            return Status.APPLIED;
        }
        return control.observation().filter(observation -> !observation.validUntil().isAfter(at)).isPresent()
                ? Status.EXPIRED
                : Status.DENIED;
    }

    private static Status admissionStatus(Locked locked) {
        if (locked.control().isEmpty()) {
            return Status.DENIED;
        }
        ControlSnapshot control = locked.control().orElseThrow();
        RunSnapshot run = locked.run();
        if (run.controlGeneration() != control.version().generation()
                || run.attempt().controlGeneration() != run.controlGeneration()) {
            return Status.STALE;
        }
        if (!control.enabled()
                || control.pins().filter(pins -> pins.equals(ControlPins.forAttempt(run.attempt().spec()))).isEmpty()) {
            return Status.DENIED;
        }
        Status evidence = evidenceStatus(control, locked.at());
        if (evidence != Status.APPLIED) {
            return evidence;
        }
        return run.attempt().state() == AttemptState.CLAIMED && run
                .attempt()
                .claim()
                .filter(claim -> claim.leaseUntil().isAfter(control.observation().orElseThrow().validUntil()))
                .isPresent() ? Status.EXPIRED : Status.APPLIED;
    }

    private static Status checkedAdmission(Locked locked, Expected expected) {
        Status authority = admissionStatus(locked);
        return authority == Status.APPLIED ? checked(locked, expected) : authority;
    }

    private RunSnapshot snapshot(UUID runId) {
        return snapshot(runId, Optional.empty());
    }

    private RunSnapshot snapshot(UUID runId, Optional<AiRuntimeOperationBudget> budget) {
        return query(budget, () -> repository.snapshot(runId))
                .orElseThrow(() -> new IllegalStateException("Runtime snapshot is missing"));
    }

    private static Status checked(Locked locked, Expected expected) {
        if (!expected(locked.run()).equals(expected)) {
            return Status.STALE;
        }
        return liveStatus(locked);
    }

    private static Status liveStatus(Locked locked) {
        RunSnapshot run = locked.run();
        Status terminal = terminalStatus(run);
        if (terminal != Status.APPLIED) {
            return terminal;
        }
        if (run.attempt().state() == AttemptState.FENCED || !run.spec().runDeadline().isAfter(locked.at())
                || !run.attempt().spec().maxDeadline().isAfter(locked.at())) {
            return Status.EXPIRED;
        }
        if (run.attempt().state() == AttemptState.LAUNCHING) {
            return run.attempt().spec().launchDeadline().isAfter(locked.at()) ? Status.APPLIED : Status.EXPIRED;
        }
        Claim claim = run.attempt().claim().orElseThrow();
        Optional<WorkloadSnapshot> winner = workload(run, claim.binding().workload());
        if (!claim.leaseUntil().isAfter(locked.at()) || winner.isEmpty()
                || winner.orElseThrow().state() != WorkloadState.REGISTERED
                || !winner.orElseThrow().observationValidUntil().isAfter(locked.at())) {
            return Status.EXPIRED;
        }
        return Status.APPLIED;
    }

    private static Status terminalStatus(RunSnapshot run) {
        if (run.state() == RunState.CANCELLED) {
            return Status.CANCELLED;
        }
        if (run.state() == RunState.FAILED) {
            return Status.DENIED;
        }
        if (run.state() == RunState.LIMIT_REACHED) {
            return Status.LIMIT_REACHED;
        }
        return Status.APPLIED;
    }

    private static Optional<FailureReason> expiryReason(Locked locked) {
        RunSnapshot run = locked.run();
        if (run.attempt().state() == AttemptState.CLAIMED) {
            Claim claim = run.attempt().claim().orElseThrow();
            if (!claim.leaseUntil().isAfter(locked.at()) || !run.spec().runDeadline().isAfter(locked.at())
                    || !run.attempt().spec().maxDeadline().isAfter(locked.at())) {
                return Optional.of(FailureReason.LEASE_EXPIRED);
            }
            return workload(run, claim.binding().workload())
                    .filter(row -> !row.observationValidUntil().isAfter(locked.at()))
                    .map(row -> FailureReason.OBSERVATION_EXPIRED);
        }
        if (!run.attempt().spec().launchDeadline().isAfter(locked.at())
                || !run.spec().runDeadline().isAfter(locked.at())) {
            return Optional.of(FailureReason.LAUNCH_EXPIRED);
        }
        return run
                .workloads()
                .stream()
                .filter(row -> row.pendingReturns() >= 11
                        || row.pendingDeadline().filter(deadline -> !deadline.isAfter(locked.at())).isPresent())
                .findFirst()
                .map(row -> FailureReason.PENDING_EXHAUSTED);
    }

    private static boolean recoverable(FailureReason reason) {
        return reason == FailureReason.LAUNCH_EXPIRED || reason == FailureReason.LEASE_EXPIRED
                || reason == FailureReason.PENDING_EXHAUSTED || reason == FailureReason.OBSERVATION_EXPIRED;
    }

    private static boolean replacementPinsMatch(AttemptSpec previous, AttemptSpec next) {
        return !previous.attemptId().equals(next.attemptId()) && previous.imageDigest().equals(next.imageDigest())
                && previous.profileRevision() == next.profileRevision()
                && previous.securityRevision() == next.securityRevision()
                && previous.trustRevision() == next.trustRevision() && previous.protocol().equals(next.protocol())
                && previous.launch().equals(next.launch());
    }

    private static Status observationStatus(Optional<WorkloadSnapshot> existing, WorkloadObservation observation) {
        if (existing.isEmpty()) {
            return Status.APPLIED;
        }
        WorkloadSnapshot row = existing.orElseThrow();
        if (!row.podName().equals(observation.podName()) || !row.jobUid().equals(observation.jobUid())
                || row.state() == WorkloadState.CLOSED
                || (row.state() == WorkloadState.REGISTERED && !observation.registered())
                || observation.sequence() < row.observationSequence()) {
            return Status.CONFLICT;
        }
        if (observation.sequence() == row.observationSequence()) {
            return row.observationValidUntil().equals(observation.validUntil())
                    && (row.state() == WorkloadState.REGISTERED) == observation.registered()
                            ? Status.REPLAY
                            : Status.CONFLICT;
        }
        return Status.APPLIED;
    }

    private static boolean pinsMatch(RunSnapshot run, WorkloadObservation o) {
        AttemptSpec attempt = run.attempt().spec();
        LaunchSpec launch = run.launch().spec();
        return launch.cluster().equals(o.cluster()) && launch.namespaceName().equals(o.namespaceName())
                && launch.namespaceUid().equals(o.namespaceUid())
                && launch.serviceAccountName().equals(o.serviceAccountName())
                && launch.serviceAccountUid().equals(o.serviceAccountUid())
                && run.launch().jobName().equals(o.jobName()) && attempt.imageDigest().equals(o.imageDigest())
                && launch.templateDigest().equals(o.templateDigest()) && launch.runtimeClass().equals(o.runtimeClass())
                && attempt.profileRevision() == o.profileRevision()
                && attempt.securityRevision() == o.securityRevision() && attempt.trustRevision() == o.trustRevision()
                && attempt.protocol().equals(o.protocol());
    }

    private void fence(Locked locked, FailureReason reason, RunState state) {
        fence(locked, reason, state, Optional.empty());
    }

    private void fence(Locked locked, FailureReason reason, RunState state, Optional<AiRuntimeOperationBudget> budget) {
        applied(query(budget, () -> repository.fence(expected(locked.run()), reason, state, locked.at())));
    }

    private static RunState recoverableState(Locked locked) {
        return locked.run().attemptsUsed() < locked.run().spec().attemptLimit()
                && locked.run().spec().runDeadline().isAfter(locked.at()) ? RunState.QUEUED : RunState.LIMIT_REACHED;
    }

    private static Instant leaseUntil(Locked locked) {
        return earlier(locked.at().plusSeconds(locked.run().spec().leaseSeconds()),
                earlier(locked.run().attempt().spec().maxDeadline(), earlier(locked.run().spec().runDeadline(),
                        locked.control().orElseThrow().observation().orElseThrow().validUntil())));
    }

    private boolean admissionCurrent(Expected expected, Optional<Instant> operationDeadline,
            Optional<AiRuntimeOperationBudget> budget) {
        if (operationDeadline.isEmpty()) {
            return query(budget, () -> repository.admissionCurrent(expected));
        }
        if (!query(budget, () -> repository.admissionCurrentBefore(expected, operationDeadline.orElseThrow()))) {
            // The diagnostic can only refine a denial; it must never revive a bounded replay.
            if (!query(budget, () -> repository.admissionCurrent(expected))) {
                return false;
            }
            throw new AiRuntimeOperationBudget.Unavailable(Thread.currentThread().isInterrupted());
        }
        return true;
    }

    private <T> T query(Optional<AiRuntimeOperationBudget> budget, Supplier<T> operation) {
        if (budget.isPresent()) {
            return database.query(budget.orElseThrow(), operation);
        }
        return operation.get();
    }

    private static Instant earlier(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }

    private static Optional<WorkloadSnapshot> workload(RunSnapshot run, WorkloadRef ref) {
        return run.workloads().stream().filter(row -> row.ref().equals(ref)).findFirst();
    }

    private static Expected expected(RunSnapshot run) {
        return new Expected(run.spec().runId(), run.attempt().spec().attemptId(), run.revision(), run.fence());
    }

    private static void applied(int affected) {
        if (affected != 1) {
            throw new Rejected();
        }
    }

    private record Locked(RunSnapshot run, Instant at, Optional<ControlSnapshot> control) {
    }

    private record LockedControl(ControlSnapshot control, Instant at) {
    }

    public static final class Rejected extends RuntimeException implements PlatformException {
        public Rejected() {
            super("Runtime transition was not applied");
        }
    }
}
