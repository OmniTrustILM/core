package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.controller.ControllerProfile;
import com.otilm.ai.controller.ControllerWire;
import com.otilm.ai.controller.KubernetesApi;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.controller.KubernetesObserver;
import com.otilm.ai.controller.KubernetesSnapshotVerifier;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.ai.runtime.protocol.RuntimeErrorReply;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.security.ai.AiRuntimeControllerAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.AiRuntimeControllerExternalService;
import com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Independently observed native controller operations; all decoded identifiers remain copyable labels. */
@Service
@TraceMetadataOnly
public class AiRuntimeControllerServiceImpl implements AiRuntimeControllerExternalService {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeControllerServiceImpl.class);
    private static final ObjectMapper JSON = ObjectMapperFactory.aiKubernetesWire();
    private static final long TERMINAL_NANOS = Duration.ofSeconds(30).toNanos();
    private final AiFeatureGate feature;
    private final AiRuntimeKernel kernel;
    private final AiRuntimeCleanupWriter cleanup;
    private final ObjectProvider<AiRuntimeControllerAuthority> authorities;
    private final ObjectProvider<Source> sources;
    private final Clock clock;
    private final LongSupplier nanos;
    private final AtomicBoolean observing = new AtomicBoolean();
    private final AtomicReference<Termination> terminal = new AtomicReference<>();
    private final ProtocolCodec errors = new ProtocolCodec();
    private volatile KubernetesApi quarantined;

    public record Source(KubernetesConfiguration api, Map<RuntimePeerRole, Path> workloadProfiles) {
        public Source {
            Objects.requireNonNull(api);
            if (workloadProfiles == null || !workloadProfiles
                    .keySet()
                    .equals(Set
                            .of(RuntimePeerRole.RUNNER_PROXY, RuntimePeerRole.GATEWAY_RUN,
                                    RuntimePeerRole.GATEWAY_MANAGEMENT))) {
                throw new IllegalArgumentException("Invalid runtime observation source");
            }
            for (Path profile : workloadProfiles.values()) {
                if (profile == null || !profile.isAbsolute() || profile.getParent() == null
                        || !profile.normalize().equals(profile)) {
                    throw new IllegalArgumentException("Invalid runtime observation source");
                }
            }
            workloadProfiles = Map.copyOf(workloadProfiles);
        }

        @Override
        public String toString() {
            return "Source[redacted]";
        }
    }

    @Autowired
    public AiRuntimeControllerServiceImpl(AiRuntimeKernel kernel, AiRuntimeCleanupWriter cleanup,
            ObjectProvider<AiRuntimeControllerAuthority> authorities, ObjectProvider<Source> sources,
            AiFeatureGate feature) {
        this(kernel, cleanup, authorities, sources, Clock.systemUTC(), System::nanoTime, feature);
    }

    AiRuntimeControllerServiceImpl(AiRuntimeKernel kernel, AiRuntimeCleanupWriter cleanup,
            ObjectProvider<AiRuntimeControllerAuthority> authorities, ObjectProvider<Source> sources, Clock clock,
            LongSupplier nanos, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.kernel = Objects.requireNonNull(kernel);
        this.cleanup = Objects.requireNonNull(cleanup);
        this.authorities = Objects.requireNonNull(authorities);
        this.sources = Objects.requireNonNull(sources);
        this.clock = Objects.requireNonNull(clock);
        this.nanos = Objects.requireNonNull(nanos);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> reconcile(InputStream body) {
        return execute(body, AiRuntimeControllerWire.Route.RECONCILE);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> register(InputStream body) {
        return execute(body, AiRuntimeControllerWire.Route.REGISTER);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> status(InputStream body) {
        return execute(body, AiRuntimeControllerWire.Route.STATUS);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> cleanup(InputStream body) {
        return execute(body, AiRuntimeControllerWire.Route.CLEANUP);
    }

    private boolean isAdmissionDisabled(AiRuntimeControllerWire.Route route) {
        return !feature.enabled() && (route == AiRuntimeControllerWire.Route.RECONCILE
                || route == AiRuntimeControllerWire.Route.REGISTER);
    }

    private ResponseEntity<byte[]> execute(InputStream body, AiRuntimeControllerWire.Route route) {
        if (isAdmissionDisabled(route)) {
            return error(route, RuntimeErrorCode.DENIED);
        }
        var step = new Step(AiRuntimeOperationBudget.start(nanos));
        boolean owned = false;
        try {
            var peer = controllerPeer();
            if (quarantined != null || !observing.compareAndSet(false, true)) {
                throw rejected(RuntimeErrorCode.UNAVAILABLE);
            }
            owned = true;
            authorizeStep(peer, step);
            var request = AiRuntimeControllerWire.read(AiRuntimeRequestBody.read(body, 4096, step.budget), route);
            var run = current(request.locator(), step.budget);
            byte[] response = dispatch(request, run, step);
            step.budget.remaining();
            return response(200, response);
        } catch (AiRuntimeControllerWire.Invalid invalid) {
            return error(route, RuntimeErrorCode.INVALID_REQUEST);
        } catch (AiRuntimeRequestBody.LimitExceeded limit) {
            return error(route, RuntimeErrorCode.LIMIT_EXCEEDED);
        } catch (Rejected denied) {
            return error(route, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : denied.code);
        } catch (AccessDeniedException denied) {
            terminal.set(null);
            return error(route, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : RuntimeErrorCode.DENIED);
        } catch (Exception unavailable) {
            terminal.set(null);
            return error(route, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : RuntimeErrorCode.UNAVAILABLE);
        } finally {
            if (owned) {
                releaseObservation(step);
            }
        }
    }

    private RuntimePeer controllerPeer() {
        var peer = RuntimeProxyTransport
                .currentWorkloadPeer()
                .orElseThrow(() -> rejected(RuntimeErrorCode.UNAUTHENTICATED));
        if (peer.role() != RuntimePeerRole.CONTROLLER) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return peer;
    }

    private void authorizeStep(RuntimePeer peer, Step step) {
        var authority = authorities.getIfUnique();
        step.source = sources.getIfUnique();
        if (authority == null || step.source == null) {
            throw rejected(RuntimeErrorCode.UNAVAILABLE);
        }
        authority.requireCurrent(peer, step.budget);
        step.authority = authority;
        step.peer = peer;
    }

    private byte[] dispatch(AiRuntimeControllerWire.Request request, AiRuntimeState.RunSnapshot run, Step step)
            throws Exception {
        return switch (request.kind()) {
            case LAUNCH -> launch(request.locator(), run, step);
            case ELIGIBLE -> observe(request, run, false, step);
            case REGISTER -> observe(request, run, true, step);
            case STATUS -> ControllerWire
                    .controlReply(ControllerWire.ControlOperation.STATUS, new ControllerWire.ControlReply(
                            control(request.locator(), run), run.state().name(), run.attempt().state().name(), null));
            case RESUME -> resume(request.locator(), run);
            case FENCE -> fence(request.locator(), run, step);
            case TERMINAL -> terminal(request, run, step);
            case CLEANUP -> complete(request, run, step);
        };
    }

    private void releaseObservation(Step step) {
        if (step.api != null && step.api.cleanupUncertain()) {
            quarantined = step.api;
            terminal.set(null);
        } else {
            observing.set(false);
        }
    }

    private byte[] launch(ControllerWire.Locator locator, AiRuntimeState.RunSnapshot run, Step step) {
        admitted(run, step.budget);
        if (run.state() != AiRuntimeState.RunState.QUEUED
                || run.attempt().state() != AiRuntimeState.AttemptState.LAUNCHING) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        var reply = binding(locator, run);
        profile(step).requireLaunch(reply);
        step.budget.remaining();
        return ControllerWire.launchReply(reply);
    }

    private byte[] observe(AiRuntimeControllerWire.Request request, AiRuntimeState.RunSnapshot run, boolean registered,
            Step step) throws Exception {
        var control = admitted(run, step.budget);
        var profile = profile(step);
        profile.requireLaunch(binding(request.locator(), run));
        var pins = actualPod(profile, run, request.podUid(), step);
        var evidence = KubernetesObserver
                .observe(step.api, pins,
                        registered ? KubernetesSnapshotVerifier.Stage.RUNNING : KubernetesSnapshotVerifier.Stage.GATED);
        known(step);
        Instant until = earlier(clock.instant().plusSeconds(20), earlier(run.attempt().spec().maxDeadline(),
                earlier(run.spec().runDeadline(), control.observation().orElseThrow().validUntil())));
        long sequence = Math.addExact(run.launch().observationSequence(), 1);
        var expected = expected(run);
        var launch = run.launch().spec();
        var attempt = run.attempt().spec();
        var observation = new AiRuntimeState.WorkloadObservation(expected, launch.cluster(), pins.namespaceName(),
                pins.namespaceUid(), pins.serviceAccountName(), pins.serviceAccountUid(), pins.jobName(), pins.jobUid(),
                pins.podName(), pins.podUid(), attempt.imageDigest(), launch.templateDigest(), pins.runtimeClass(),
                attempt.profileRevision(), attempt.securityRevision(), attempt.trustRevision(), attempt.protocol(),
                sequence, until, registered);
        step.writerStarted = true;
        accepted(kernel.observe(observation, step.budget));
        var after = current(request.locator(), step.budget);
        var row = after
                .workloads()
                .stream()
                .filter(w -> w.ref().equals(new AiRuntimeState.WorkloadRef(launch.cluster(), pins.podUid())))
                .findFirst()
                .orElseThrow(() -> rejected(RuntimeErrorCode.UNKNOWN_OUTCOME));
        if (after.fence() != run.fence() || !pins.jobUid().equals(row.jobUid())
                || row.state() == AiRuntimeState.WorkloadState.CLOSED || row.observationSequence() != sequence
                || registered && row.state() != AiRuntimeState.WorkloadState.REGISTERED) {
            throw rejected(RuntimeErrorCode.UNKNOWN_OUTCOME);
        }
        var operation = registered ? ControllerWire.Operation.REGISTER : ControllerWire.Operation.ELIGIBLE;
        return ControllerWire
                .observationReply(operation,
                        new ControllerWire.ObservationReply(
                                new ControllerWire.ObservationRequest(request.locator(), request.podUid()),
                                UUID.fromString(pins.jobUid()), evidence.workload().podResourceVersion(),
                                after.revision(), after.fence(), sequence, row.observationValidUntil()));
    }

    private byte[] resume(ControllerWire.Locator locator, AiRuntimeState.RunSnapshot run) {
        if (run.attempt().state() != AiRuntimeState.AttemptState.FENCED || run.launch().jobUid().isEmpty()
                || run.workloads().isEmpty() || run.launch().cleanup() != AiRuntimeState.CleanupState.DUE
                        && run.launch().cleanup() != AiRuntimeState.CleanupState.DONE) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        terminal.set(null);
        var operation = run.launch().cleanup() == AiRuntimeState.CleanupState.DONE
                ? ControllerWire.ControlOperation.CLEANUP
                : ControllerWire.ControlOperation.FENCE;
        return ControllerWire
                .controlReply(operation, new ControllerWire.ControlReply(control(locator, run), null, null, null));
    }

    private byte[] fence(ControllerWire.Locator locator, AiRuntimeState.RunSnapshot run, Step step) {
        terminal.set(null);
        if (run.attempt().state() != AiRuntimeState.AttemptState.FENCED) {
            step.writerStarted = true;
            accepted(kernel.invalidate(expected(run), step.budget));
        }
        var after = current(locator, step.budget);
        fenced(after);
        return ControllerWire
                .controlReply(ControllerWire.ControlOperation.FENCE,
                        new ControllerWire.ControlReply(control(locator, after), null, null, null));
    }

    private byte[] terminal(AiRuntimeControllerWire.Request request, AiRuntimeState.RunSnapshot run, Step step)
            throws Exception {
        terminal.set(null);
        exact(request, run);
        fenced(run);
        if (run.workloads().isEmpty() || run.workloads().size() > 16) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        long observed = nanos.getAsLong();
        var profile = profile(step);
        profile.requireLaunch(binding(request.locator(), run));
        for (var workload : run.workloads()) {
            var pins = actualPod(profile, run, UUID.fromString(workload.ref().podUid()), step);
            KubernetesObserver.observe(step.api, pins, KubernetesSnapshotVerifier.Stage.TERMINAL);
            known(step);
        }
        exact(request, current(request.locator(), step.budget));
        var proof = new Termination(expected(run), run.launch().jobUid().orElseThrow(), refs(run), observed);
        long remaining = terminalRemaining(observed);
        terminal.set(proof);
        return ControllerWire
                .controlReply(ControllerWire.ControlOperation.TERMINAL, new ControllerWire.ControlReply(
                        request.expected(), null, null, clock.instant().plusNanos(remaining)));
    }

    private byte[] complete(AiRuntimeControllerWire.Request request, AiRuntimeState.RunSnapshot run, Step step)
            throws Exception {
        exact(request, run);
        fenced(run);
        var proof = terminal.get();
        if (proof == null || !proof.expected.equals(expected(run))
                || !proof.jobUid.equals(run.launch().jobUid().orElse(null)) || !proof.workloads.equals(refs(run))
                || !fresh(proof)) {
            terminal.set(null);
            throw rejected(RuntimeErrorCode.DENIED);
        }
        var profile = profile(step);
        profile.requireLaunch(binding(request.locator(), run));
        var job = parse(profile.job());
        String namespace = text(job.path("metadata"), "namespace");
        String name = text(job.path("metadata"), "name");
        step.api = step.source.api().open(step.budget.remaining());
        requireNamespace(step.api.namespace(namespace), namespace, run.launch().spec().namespaceUid());
        if (!step.api.jobAbsent(namespace, name, proof.jobUid)) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        byte[] listed = step.api.pods(namespace);
        if (!profile.findPods(listed, proof.jobUid).isEmpty()) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        var knownNames = run
                .workloads()
                .stream()
                .map(AiRuntimeState.WorkloadSnapshot::podName)
                .collect(java.util.stream.Collectors.toSet());
        for (var pod : parse(listed).path("items")) {
            String uid = text(pod.path("metadata"), "uid");
            if (proof.workloads.stream().anyMatch(ref -> ref.podUid().equals(uid))
                    || knownNames.contains(text(pod.path("metadata"), "name"))) {
                throw rejected(RuntimeErrorCode.DENIED);
            }
        }
        requireNamespace(step.api.namespace(namespace), namespace, run.launch().spec().namespaceUid());
        known(step);
        exact(request, current(request.locator(), step.budget));
        if (!fresh(proof) || !terminal.compareAndSet(proof, null)) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        step.writerStarted = true;
        accepted(cleanup.complete(expected(run), proof.jobUid, proof.workloads, step.budget));
        return ControllerWire
                .controlReply(ControllerWire.ControlOperation.CLEANUP,
                        new ControllerWire.ControlReply(request.expected(), null, null, null));
    }

    private boolean fresh(Termination proof) {
        long elapsed = nanos.getAsLong() - proof.observed;
        return elapsed >= 0 && elapsed < TERMINAL_NANOS;
    }

    private long terminalRemaining(long observed) {
        long elapsed = nanos.getAsLong() - observed;
        if (elapsed < 0 || elapsed >= TERMINAL_NANOS) {
            throw rejected(RuntimeErrorCode.UNAVAILABLE);
        }
        return TERMINAL_NANOS - elapsed;
    }

    private static void requireNamespace(byte[] body, String name, String uid) throws Exception {
        var namespace = parse(body);
        var metadata = namespace.path("metadata");
        if (!"v1".equals(namespace.path("apiVersion").textValue())
                || !"Namespace".equals(namespace.path("kind").textValue())
                || !name.equals(metadata.path("name").textValue()) || !uid.equals(metadata.path("uid").textValue())
                || metadata.hasNonNull("namespace") || metadata.hasNonNull("deletionTimestamp")) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
    }

    private KubernetesSnapshotVerifier.Pins actualPod(ControllerProfile profile, AiRuntimeState.RunSnapshot run,
            UUID wanted, Step step) throws Exception {
        var job = parse(profile.job());
        String namespace = text(job.path("metadata"), "namespace");
        String name = text(job.path("metadata"), "name");
        step.api = step.source.api().open(step.budget.remaining());
        String jobUid = text(parse(step.api.job(namespace, name)).path("metadata"), "uid");
        if (!UUID.fromString(jobUid).toString().equals(jobUid)
                || run.launch().jobUid().filter(old -> !old.equals(jobUid)).isPresent()) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        var owned = profile.findPods(step.api.pods(namespace), jobUid);
        if (run.attempt().state() == AiRuntimeState.AttemptState.FENCED && !owned
                .stream()
                .map(KubernetesSnapshotVerifier.Pins::podUid)
                .collect(java.util.stream.Collectors.toSet())
                .equals(run
                        .workloads()
                        .stream()
                        .map(row -> row.ref().podUid())
                        .collect(java.util.stream.Collectors.toSet()))) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        var pins = owned
                .stream()
                .filter(pod -> pod.podUid().equals(wanted.toString()))
                .findFirst()
                .orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
        if (run
                .workloads()
                .stream()
                .anyMatch(row -> row.ref().podUid().equals(wanted.toString())
                        && (!row.podName().equals(pins.podName()) || !row.jobUid().equals(jobUid)))) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return pins;
    }

    private ControllerProfile profile(Step step) {
        step.budget.remaining();
        var result = ControllerProfile.read(step.source.workloadProfiles().get(RuntimePeerRole.RUNNER_PROXY));
        result.requireRunnerDeadline();
        step.budget.remaining();
        return result;
    }

    private AiRuntimeState.ControlSnapshot admitted(AiRuntimeState.RunSnapshot run, AiRuntimeOperationBudget budget) {
        var control = kernel.control(budget).orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
        if (!control.usableAt(clock.instant()) || control.version().generation() != run.controlGeneration()
                || control
                        .pins()
                        .filter(value -> value.equals(AiRuntimeState.ControlPins.forAttempt(run.attempt().spec())))
                        .isEmpty()) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return control;
    }

    private AiRuntimeState.RunSnapshot current(ControllerWire.Locator locator, AiRuntimeOperationBudget budget) {
        var run = kernel.snapshot(locator.runId(), budget).orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
        if (!locator.runId().equals(run.spec().runId())
                || !locator.attemptId().equals(run.attempt().spec().attemptId())) {
            throw rejected(RuntimeErrorCode.STALE_BINDING);
        }
        return run;
    }

    private static ControllerWire.Launch binding(ControllerWire.Locator locator, AiRuntimeState.RunSnapshot run) {
        var attempt = run.attempt().spec();
        var spec = run.launch().spec();
        return new ControllerWire.Launch(locator, run.revision(), run.fence(), attempt.launchDeadline(),
                attempt.maxDeadline(), attempt.imageDigest(), attempt.profileRevision(), attempt.securityRevision(),
                attempt.trustRevision(), attempt.protocol(), spec.cluster(), spec.namespaceName(),
                UUID.fromString(spec.namespaceUid()), spec.serviceAccountName(),
                UUID.fromString(spec.serviceAccountUid()), spec.templateDigest(), spec.runtimeClass(),
                run.launch().jobName());
    }

    private static ControllerWire.Control control(ControllerWire.Locator locator, AiRuntimeState.RunSnapshot run) {
        return new ControllerWire.Control(locator, run.revision(), run.fence(),
                run.launch().jobUid().map(UUID::fromString).orElse(null),
                refs(run)
                        .stream()
                        .map(ref -> new ControllerWire.Pod(ref.cluster(), UUID.fromString(ref.podUid())))
                        .collect(java.util.stream.Collectors.toSet()));
    }

    private static Set<AiRuntimeState.WorkloadRef> refs(AiRuntimeState.RunSnapshot run) {
        var refs = new HashSet<AiRuntimeState.WorkloadRef>();
        for (var row : run.workloads()) {
            if (!refs.add(row.ref())) {
                throw rejected(RuntimeErrorCode.DENIED);
            }
        }
        return Set.copyOf(refs);
    }

    private static AiRuntimeState.Expected expected(AiRuntimeState.RunSnapshot run) {
        return new AiRuntimeState.Expected(run.spec().runId(), run.attempt().spec().attemptId(), run.revision(),
                run.fence());
    }

    private static void exact(AiRuntimeControllerWire.Request request, AiRuntimeState.RunSnapshot run) {
        if (!control(request.locator(), run).equals(request.expected())) {
            throw rejected(RuntimeErrorCode.STALE_BINDING);
        }
    }

    private static void fenced(AiRuntimeState.RunSnapshot run) {
        if (run.attempt().state() != AiRuntimeState.AttemptState.FENCED
                || run.launch().cleanup() != AiRuntimeState.CleanupState.DUE || run.launch().jobUid().isEmpty()) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
    }

    private static void accepted(AiRuntimeState.Transition<?> result) {
        if (result.status() != AiRuntimeState.Status.APPLIED && result.status() != AiRuntimeState.Status.REPLAY) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
    }

    private static void known(Step step) {
        if (step.api != null && step.api.cleanupUncertain()) {
            throw rejected(RuntimeErrorCode.UNAVAILABLE);
        }
        step.budget.remaining();
        step.authority.requireCurrent(step.peer, step.budget);
    }

    private static JsonNode parse(byte[] bytes) throws Exception {
        if (bytes == null || bytes.length > 1_048_576) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return JSON.readTree(StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString());
    }

    private static String text(JsonNode node, String field) {
        if (!node.path(field).isTextual() || node.path(field).textValue().isBlank()) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return node.path(field).textValue();
    }

    private static Instant earlier(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }

    private ResponseEntity<byte[]> error(AiRuntimeControllerWire.Route route, RuntimeErrorCode code) {
        UUID correlation = UUID.randomUUID();
        LOG.debug("AI controller operation={} code={} correlation={}", route, code, correlation);
        int status = switch (code) {
            case UNAUTHENTICATED -> 401;
            case DENIED -> 403;
            case INVALID_REQUEST, UNSUPPORTED_VERSION -> 400;
            case LIMIT_EXCEEDED -> 413;
            default -> 503;
        };
        return response(status, errors.writeRuntimeError(new RuntimeErrorReply(1, code, correlation)));
    }

    private static ResponseEntity<byte[]> response(int status, byte[] bytes) {
        return ResponseEntity
                .status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .body(bytes);
    }

    private static Rejected rejected(RuntimeErrorCode code) {
        return new Rejected(code);
    }

    private static final class Rejected extends RuntimeException implements PlatformException {
        private final RuntimeErrorCode code;

        private Rejected(RuntimeErrorCode code) {
            super(code.name(), null, false, false);
            this.code = code;
        }
    }

    private record Termination(AiRuntimeState.Expected expected, String jobUid,
            Set<AiRuntimeState.WorkloadRef> workloads, long observed) {
        private Termination {
            workloads = Set.copyOf(workloads);
        }
    }

    private static final class Step {
        private final AiRuntimeOperationBudget budget;
        private Source source;
        private AiRuntimeControllerAuthority authority;
        private RuntimePeer peer;
        private KubernetesApi api;
        private boolean writerStarted;

        private Step(AiRuntimeOperationBudget budget) {
            this.budget = budget;
        }
    }
}
