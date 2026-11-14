package com.otilm.core.service.ai;

import com.otilm.ai.controller.KubernetesApi;
import com.otilm.ai.controller.KubernetesObserver;
import com.otilm.ai.controller.KubernetesSnapshotVerifier;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.ai.runtime.protocol.RuntimeErrorReply;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiRuntimeGatewayState;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.security.ai.AiRuntimeControllerAuthority;
import com.otilm.core.security.ai.AiRuntimeNativeMaterialPublisher;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.AiRuntimeControllerRegistrationExternalService;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
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

/** Current controller/API registration seam; it neither proves Node enforcement nor enables business execution. */
@Service
@TraceMetadataOnly
public class AiRuntimeControllerRegistrationServiceImpl implements AiRuntimeControllerRegistrationExternalService {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeControllerRegistrationServiceImpl.class);
    private final ObjectProvider<AiRuntimeControllerAuthority> authorities;
    private final ObjectProvider<AiRuntimeControllerServiceImpl.Source> sources;
    private final ObjectProvider<AiRuntimeNativeMaterialPublisher> policies;
    private final AiRuntimeGatewayRegistrationWriter runWriter;
    private final AiRuntimeManagementGatewayWriter managementWriter;
    private final Clock clock;
    private final LongSupplier nanos;
    private final AtomicBoolean observing = new AtomicBoolean();
    private final ProtocolCodec errors = new ProtocolCodec();
    private volatile KubernetesApi quarantined;

    @Autowired
    public AiRuntimeControllerRegistrationServiceImpl(ObjectProvider<AiRuntimeControllerAuthority> authorities,
            ObjectProvider<AiRuntimeControllerServiceImpl.Source> sources,
            ObjectProvider<AiRuntimeNativeMaterialPublisher> policies, AiRuntimeGatewayRegistrationWriter runWriter,
            AiRuntimeManagementGatewayWriter managementWriter) {
        this(authorities, sources, policies, runWriter, managementWriter, Clock.systemUTC(), System::nanoTime);
    }

    AiRuntimeControllerRegistrationServiceImpl(ObjectProvider<AiRuntimeControllerAuthority> authorities,
            ObjectProvider<AiRuntimeControllerServiceImpl.Source> sources,
            ObjectProvider<AiRuntimeNativeMaterialPublisher> policies, AiRuntimeGatewayRegistrationWriter runWriter,
            AiRuntimeManagementGatewayWriter managementWriter, Clock clock, LongSupplier nanos) {
        this.authorities = Objects.requireNonNull(authorities);
        this.sources = Objects.requireNonNull(sources);
        this.policies = Objects.requireNonNull(policies);
        this.runWriter = Objects.requireNonNull(runWriter);
        this.managementWriter = Objects.requireNonNull(managementWriter);
        this.clock = Objects.requireNonNull(clock);
        this.nanos = Objects.requireNonNull(nanos);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> observeRunGateway() {
        return observe(false);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> observeManagementGateway() {
        return observe(true);
    }

    private ResponseEntity<byte[]> observe(boolean management) {
        var step = new ObservationStep(AiRuntimeOperationBudget.start(nanos));
        boolean owned = false;
        try {
            var peer = controllerPeer();
            if (quarantined != null || !observing.compareAndSet(false, true)) {
                throw rejected(RuntimeErrorCode.UNAVAILABLE);
            }
            owned = true;
            return observeGateway(management, peer, step);
        } catch (Rejected denied) {
            return error(management, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : denied.code);
        } catch (AccessDeniedException denied) {
            return error(management, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : RuntimeErrorCode.DENIED);
        } catch (Exception unavailable) {
            return error(management,
                    step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : RuntimeErrorCode.UNAVAILABLE);
        } finally {
            if (owned) {
                releaseObservation(step.api);
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

    private ResponseEntity<byte[]> observeGateway(boolean management, RuntimePeer peer, ObservationStep step)
            throws Exception {
        var budget = step.budget;
        var authority = authorities.getIfUnique();
        var source = sources.getIfUnique();
        var policy = policies.getIfUnique();
        if (authority == null || source == null || policy == null) {
            throw rejected(RuntimeErrorCode.UNAVAILABLE);
        }
        var before = policy.current().orElseThrow(() -> rejected(RuntimeErrorCode.UNAVAILABLE));
        authority.requireCurrent(peer, budget);
        RuntimePeerRole role = management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN;
        var profile = AiRuntimeWorkloadProfile.read(source.workloadProfiles().get(role), budget);
        AiRuntimeGatewayState.Deployment run = management
                ? null
                : runWriter.deployment(budget).orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
        AiRuntimeManagementGatewayState.Deployment independent = !management
                ? null
                : managementWriter.deployment(budget).orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
        var image = management ? independent.pins().imageDigest() : run.imageDigest();
        var launch = management ? independent.pins().launch() : run.launch();
        if (!profile.pins().imageDigest().equals(image) || !profile.pins().launch().equals(launch)) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        Instant observed = clock.instant();
        step.api = source.api().open(budget.remaining());
        var pins = findPod(step.api, profile, launch);
        var evidence = KubernetesObserver.observe(step.api, pins, KubernetesSnapshotVerifier.Stage.RUNNING);
        if (step.api.cleanupUncertain() || clock.instant().isBefore(observed)) {
            throw rejected(RuntimeErrorCode.UNAVAILABLE);
        }
        authority.requireCurrent(peer, budget);
        profile.requireUnchanged(budget);
        requireCurrentDeployment(management, run, independent, budget);
        var after = policy.current().orElseThrow(() -> rejected(RuntimeErrorCode.UNAVAILABLE));
        if (before.revision() != after.revision()) {
            throw rejected(RuntimeErrorCode.STALE_BINDING);
        }
        Instant until = earlier(observed.plusSeconds(30),
                earlier(before.policy().expiresAt(), after.policy().expiresAt()));
        if (!clock.instant().isBefore(until)) {
            throw rejected(RuntimeErrorCode.EXPIRED);
        }
        var subject = new RuntimeProxyCertificateClaims(launch.cluster(), pins.namespaceName(),
                pins.serviceAccountName(), pins.podName(), UUID.fromString(evidence.workload().podUid()));
        recordObservation(management, run, independent, subject, observed, until, step);
        budget.remaining();
        String kind = (management ? "management" : "run") + "-gateway-observation-recorded";
        return response(200, ("{\"version\":1,\"kind\":\"" + kind + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    private KubernetesSnapshotVerifier.Pins findPod(KubernetesApi api, AiRuntimeWorkloadProfile profile,
            AiRuntimeState.LaunchSpec launch) throws IOException {
        var job = ObjectMapperFactory
                .aiKubernetesWire()
                .readTree(StandardCharsets.UTF_8
                        .newDecoder()
                        .decode(ByteBuffer.wrap(api.job(launch.namespaceName(), profile.jobName())))
                        .toString());
        var metadata = job.path("metadata");
        UUID uid = UUID.fromString(metadata.path("uid").textValue());
        if (!"batch/v1".equals(job.path("apiVersion").textValue()) || !"Job".equals(job.path("kind").textValue())
                || !profile.jobName().equals(metadata.path("name").textValue())
                || !launch.namespaceName().equals(metadata.path("namespace").textValue())
                || metadata.hasNonNull("deletionTimestamp") || uid.equals(new UUID(0, 0))
                || !uid.toString().equals(metadata.path("uid").textValue())) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
        return profile
                .profile()
                .findPod(api.pods(launch.namespaceName()), uid.toString())
                .orElseThrow(() -> rejected(RuntimeErrorCode.DENIED));
    }

    private void requireCurrentDeployment(boolean management, AiRuntimeGatewayState.Deployment run,
            AiRuntimeManagementGatewayState.Deployment independent, AiRuntimeOperationBudget budget) {
        if (management
                ? !managementWriter.deployment(budget).filter(independent::equals).isPresent()
                : !runWriter.deployment(budget).filter(run::equals).isPresent()) {
            throw rejected(RuntimeErrorCode.STALE_BINDING);
        }
    }

    private void recordObservation(boolean management, AiRuntimeGatewayState.Deployment run,
            AiRuntimeManagementGatewayState.Deployment independent, RuntimeProxyCertificateClaims subject,
            Instant observed, Instant until, ObservationStep step) {
        var budget = step.budget;
        long sequence = management
                ? managementWriter.nextObservationSequence(independent.revision(), budget)
                : runWriter.nextObservationSequence(run.controlGeneration(), budget);
        budget.remaining();
        step.writerStarted = true;
        if (management) {
            var result = managementWriter
                    .observe(new AiRuntimeManagementGatewayState.Observation(independent, subject, sequence,
                            UUID.randomUUID(), observed, until), budget);
            if (result.status() != AiRuntimeState.Status.APPLIED && result.status() != AiRuntimeState.Status.REPLAY) {
                throw rejected(RuntimeErrorCode.DENIED);
            }
        } else if (!runWriter
                .observe(new AiRuntimeGatewayState.Observation(run, subject, sequence, UUID.randomUUID(), observed,
                        until), budget)) {
            throw rejected(RuntimeErrorCode.DENIED);
        }
    }

    private void releaseObservation(KubernetesApi api) {
        if (api != null && api.cleanupUncertain()) {
            quarantined = api;
        } else {
            observing.set(false);
        }
    }

    private static final class ObservationStep {
        private final AiRuntimeOperationBudget budget;
        private KubernetesApi api;
        private boolean writerStarted;

        private ObservationStep(AiRuntimeOperationBudget budget) {
            this.budget = budget;
        }
    }

    private ResponseEntity<byte[]> error(boolean management, RuntimeErrorCode code) {
        UUID correlation = UUID.randomUUID();
        LOG
                .debug("AI gateway observation operation={} code={} correlation={}", management ? "management" : "run",
                        code, correlation);
        int status = code == RuntimeErrorCode.UNAUTHENTICATED ? 401 : code == RuntimeErrorCode.DENIED ? 403 : 503;
        return response(status, errors.writeRuntimeError(new RuntimeErrorReply(1, code, correlation)));
    }

    private static ResponseEntity<byte[]> response(int status, byte[] body) {
        return ResponseEntity
                .status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .body(body);
    }

    private static Instant earlier(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
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
}
