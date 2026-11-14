package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.BootstrapClaimedReply;
import com.otilm.ai.runtime.protocol.BootstrapPendingReply;
import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AiRuntimeRunnerExternalService;
import com.otilm.core.util.AiRuntimeFixture;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiRuntimeRunnerServiceTest {
    private static final UUID RUN = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID ACTOR = UUID.fromString("20000000-0000-0000-0000-000000000001");
    private static final UUID POD = UUID.fromString("30000000-0000-0000-0000-000000000001");
    private static final UUID CLAIM_ID = UUID.fromString("40000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private final ProtocolCodec codec = new ProtocolCodec();
    private final AiRuntimeKernel kernel = mock(AiRuntimeKernel.class);
    private final PlatformAuthenticationClient auth = mock(PlatformAuthenticationClient.class);
    private final AtomicLong nanos = new AtomicLong(100);
    private final AiRuntimeRunnerServiceImpl service = new AiRuntimeRunnerServiceImpl(kernel, auth, nanos::get,
            new AiFeatureGate(true));
    private final AttemptSpec attempt = AiRuntimeFixture.attempt(NOW);
    private final WorkloadRef ref = new WorkloadRef("cluster-one", POD.toString());
    private final Expected expected = new Expected(RUN, attempt.attemptId(), 7, 9);
    private final Claim claim = new Claim(new ClaimBinding(RUN, attempt.attemptId(), ref, CLAIM_ID, 9),
            NOW.plusSeconds(5), 1);
    private final RuntimeProxyCertificateClaims peer = new RuntimeProxyCertificateClaims("cluster-one", "ai-proof",
            "runner", "pod-one", POD);
    private MockedStatic<RuntimeProxyTransport> transport;

    @BeforeEach
    void setup() {
        transport = mockStatic(RuntimeProxyTransport.class);
        transport.when(RuntimeProxyTransport::currentPeer).thenReturn(Optional.of(peer));
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.empty())));
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenReturn(actor(ACTOR));
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.value(Status.APPLIED, claim));
    }

    @AfterEach
    void close() {
        transport.close();
        Thread.interrupted();
    }

    @Test
    void nativePeerIsRequiredBeforeAnyBodyReadOrStateAccess() {
        transport.when(RuntimeProxyTransport::currentPeer).thenReturn(Optional.empty());
        InputStream hostile = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("body was read before peer");
            }
        };
        assertError(service.bootstrap(hostile), RuntimeErrorCode.UNAUTHENTICATED);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void knownRegisteredWorkloadChecksActualActorThenClaimsExactSnapshot() {
        ResponseEntity<byte[]> response = service.bootstrap(body());
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        var reply = (BootstrapClaimedReply) codec.readBootstrapReply(response.getBody());
        assertThat(reply.binding().claimId()).isEqualTo(CLAIM_ID);
        var order = inOrder(kernel, auth);
        var sameOperation = org.mockito.ArgumentCaptor.forClass(AiRuntimeOperationBudget.class);
        order.verify(kernel).snapshot(eq(RUN), sameOperation.capture());
        order.verify(auth).authenticateByUserUuidAuthoritatively(eq(ACTOR), any(Duration.class));
        order.verify(kernel).bootstrap(eq(expected), eq(ref), eq(sameOperation.getValue()));
    }

    @Test
    void sameWinnerReplayStillChecksCurrentActorOnEveryCall() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.value(Status.REPLAY, claim));
        assertThat(service.bootstrap(body()).getStatusCode().value()).isEqualTo(200);
        assertThat(service.bootstrap(body()).getStatusCode().value()).isEqualTo(200);
        verify(auth, times(2)).authenticateByUserUuidAuthoritatively(eq(ACTOR), any());
    }

    @Test
    void onlyAlreadyKnownEligibleWorkloadCanReturnDurablePending() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.ELIGIBLE, Optional.empty())));
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.empty(Status.PENDING));
        var reply = (BootstrapPendingReply) codec.readBootstrapReply(service.bootstrap(body()).getBody());
        assertThat(reply.retryAfterMillis()).isBetween(100, 1000);
        verify(auth).authenticateByUserUuidAuthoritatively(eq(ACTOR), any());
    }

    @Test
    void unknownRunNeverProducesPendingOrAnActorLookup() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class))).thenReturn(Optional.empty());
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void unknownPodNeverProducesPendingOrAnActorLookup() {
        RunSnapshot known = snapshot(WorkloadState.REGISTERED, Optional.empty());
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional
                        .of(new RunSnapshot(known.spec(), known.state(), 7, 9, 1, known.attempt(), known.launch(),
                                List.of(), 2, NOW, NOW)));
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {"cluster", "namespace", "serviceAccount", "podName", "podUid"})
    void everyNativeIdentityComponentMustMatchPinnedState(String field) {
        var changed = new RuntimeProxyCertificateClaims(field.equals("cluster") ? "foreign" : peer.cluster(),
                field.equals("namespace") ? "foreign" : peer.namespace(),
                field.equals("serviceAccount") ? "foreign" : peer.serviceAccount(),
                field.equals("podName") ? "foreign" : peer.podName(),
                field.equals("podUid") ? UUID.randomUUID() : peer.podUid());
        transport.when(RuntimeProxyTransport::currentPeer).thenReturn(Optional.of(changed));
        assertError(service.bootstrap(body()),
                field.equals("podUid") ? RuntimeErrorCode.DENIED : RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "anonymous", "wrongActor", "failure"})
    void actorFailureCannotReachFinalTransition(String failure) {
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> switch (failure) {
            case "null" -> null;
            case "anonymous" -> AuthenticationInfo.getAnonymousAuthenticationInfo();
            case "wrongActor" -> actor(UUID.randomUUID());
            default -> throw new IllegalStateException("synthetic-private-upstream-body");
        });
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void bodyReaderConsumesAtMost4097BytesAndDoesNotCloseContainerStream() {
        AtomicLong count = new AtomicLong();
        InputStream endless = new InputStream() {
            @Override
            public int read() {
                count.incrementAndGet();
                return ' ';
            }

            @Override
            public void close() {
                throw new AssertionError("container stream closed");
            }
        };
        assertError(service.bootstrap(endless), RuntimeErrorCode.LIMIT_EXCEEDED);
        assertThat(count.get()).isEqualTo(4097);
        verifyNoInteractions(kernel, auth);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"protocolVersion\":1,\"runId\":\"bad\"}",
            "{\"protocolVersion\":1,\"protocolVersion\":1}",
            "{} {}",
            "[]"})
    void closedCodecRejectsMalformedBodiesBeforeStateAccess(String json) {
        assertError(service.bootstrap(new ByteArrayInputStream(json.getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                RuntimeErrorCode.INVALID_REQUEST);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void stalledReadCannotStartSnapshotAfterBudgetExpires() {
        InputStream slow = new ByteArrayInputStream(codec.writeBootstrapRequest(request())) {
            @Override
            public synchronized int read(byte[] bytes, int offset, int length) {
                int read = super.read(bytes, offset, length);
                nanos.addAndGet(Duration.ofSeconds(5).toNanos());
                return read;
            }
        };
        assertError(service.bootstrap(slow), RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void authConsumingRemainingBudgetCannotStartTransition() {
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> {
            assertThat((Duration) invocation.getArgument(1)).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(5));
            nanos.addAndGet(Duration.ofSeconds(5).toNanos());
            return actor(ACTOR);
        });
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void interruptionAfterAuthPreventsTransitionAndPreservesInterrupt() {
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> {
            Thread.currentThread().interrupt();
            return actor(ACTOR);
        });
        assertError(service.bootstrap(body()), RuntimeErrorCode.INTERRUPTED);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @ParameterizedTest
    @EnumSource(value = Status.class, names = {"CANCELLED", "EXPIRED", "CONFLICT", "STALE"})
    void finalKernelRaceDecisionOverridesEarlierPositiveAuth(Status status) {
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.empty(status));
        RuntimeErrorCode code = status == Status.STALE
                ? RuntimeErrorCode.STALE_BINDING
                : RuntimeErrorCode.valueOf(status.name());
        assertError(service.bootstrap(body()), code);
        verify(auth).authenticateByUserUuidAuthoritatively(eq(ACTOR), any());
    }

    @Test
    void expiryAfterTransitionReportsUnknownOutcomeRatherThanAnUnsentClaim() {
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class))).thenAnswer(invocation -> {
            nanos.addAndGet(Duration.ofSeconds(5).toNanos());
            return Transition.value(Status.APPLIED, claim);
        });
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @Test
    void heartbeatUsesExactStoredBindingAndCurrentActor() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
        when(kernel.heartbeat(eq(claim.binding()), eq(2L), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.value(Status.APPLIED, new Claim(claim.binding(), NOW.plusSeconds(9), 2)));
        var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, CLAIM_ID, 9);
        var reply = codec
                .readClaimHeartbeatReply(service
                        .heartbeat(new ByteArrayInputStream(
                                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2))))
                        .getBody());
        assertThat(reply.sequence()).isEqualTo(2);
        assertThat(reply.binding()).isEqualTo(wire);
        verify(auth).authenticateByUserUuidAuthoritatively(eq(ACTOR), any());
        verify(kernel).heartbeat(eq(claim.binding()), eq(2L), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void suppliedHeartbeatClaimCannotReplaceStoredClaim() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
        var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, UUID.randomUUID(), 9);
        assertError(
                service
                        .heartbeat(new ByteArrayInputStream(
                                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2)))),
                RuntimeErrorCode.STALE_BINDING);
        verifyNoInteractions(auth);
        verify(kernel, never()).heartbeat(any(), anyLong(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void actualSpringProxySuspendsAmbientTransactionForCurrentActorCheck() throws Exception {
        var source = mock(DataSource.class);
        var connection = mock(java.sql.Connection.class);
        when(source.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        var manager = new DataSourceTransactionManager(source);
        var factory = new ProxyFactory(service);
        factory.addAdvice(new TransactionInterceptor(manager, new AnnotationTransactionAttributeSource()));
        var proxy = (AiRuntimeRunnerExternalService) factory.getProxy();
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            return actor(ACTOR);
        });
        new TransactionTemplate(manager).executeWithoutResult(ignored -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            assertThat(proxy.bootstrap(body()).getStatusCode().value()).isEqualTo(200);
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
        });
    }

    @Test
    void realAuthoritativeHttpCallRechecksRevocationWithoutTheAuthenticationCache() throws Exception {
        try (var server = new okhttp3.mockwebserver.MockWebServer()) {
            server.start();
            var cache = mock(com.otilm.core.security.authn.client.AuthenticationCache.class);
            var audit = mock(com.otilm.core.service.AuditLogInternalService.class);
            var actual = new PlatformAuthenticationClient(audit, new com.fasterxml.jackson.databind.ObjectMapper(),
                    cache, server.url("/").toString());
            server
                    .enqueue(new okhttp3.mockwebserver.MockResponse()
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"authenticated\":true,\"data\":{\"user\":{\"uuid\":\"" + ACTOR
                                    + "\",\"username\":\"synthetic-actor\",\"enabled\":true},\"roles\":[],\"permissions\":{}}}"));
            server
                    .enqueue(new okhttp3.mockwebserver.MockResponse()
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"authenticated\":false}"));
            var actualService = new AiRuntimeRunnerServiceImpl(kernel, actual, new AiFeatureGate(true));
            assertThat(actualService.bootstrap(body()).getStatusCode().value()).isEqualTo(200);
            assertError(actualService.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
            assertThat(server.getRequestCount()).isEqualTo(2);
            var request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(request).isNotNull();
            assertThat(request.getPath()).isEqualTo("/auth");
            assertThat(new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(request.getBody().readUtf8())
                    .path("userUuid")
                    .textValue()).isEqualTo(ACTOR.toString());
            verify(kernel, times(1)).bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class));
            verifyNoInteractions(cache, audit);
        }
    }

    @Test
    void metadataOnlyServiceTracingDoesNotSerializeTheInputStream() {
        var telemetry = mock(io.opentelemetry.api.OpenTelemetry.class);
        var tracer = mock(io.opentelemetry.api.trace.Tracer.class);
        var builder = mock(io.opentelemetry.api.trace.SpanBuilder.class);
        var span = mock(io.opentelemetry.api.trace.Span.class);
        when(telemetry.getTracer("application")).thenReturn(tracer);
        when(tracer.spanBuilder(anyString())).thenReturn(builder);
        when(builder.setSpanKind(any())).thenReturn(builder);
        when(builder.startSpan()).thenReturn(span);
        var scope = mock(io.opentelemetry.context.Scope.class);
        when(span.makeCurrent()).thenReturn(scope);
        var factory = new org.springframework.aop.aspectj.annotation.AspectJProxyFactory(service);
        factory.setProxyTargetClass(false);
        factory.addAspect(new com.otilm.core.aop.TracingAspect(telemetry));
        var proxy = (AiRuntimeRunnerExternalService) factory.getProxy();
        InputStream secret = new ByteArrayInputStream(codec.writeBootstrapRequest(request())) {
            @Override
            public String toString() {
                throw new AssertionError("input serialized to telemetry");
            }
        };
        assertThat(proxy.bootstrap(secret).getStatusCode().value()).isEqualTo(200);
        verify(span, never()).recordException(any(Throwable.class));
        verify(span).setAttribute("code.function", "bootstrap");
        verify(span).end();
    }

    @Test
    void exactly4096BytesRemainAccepted() {
        byte[] message = codec.writeBootstrapRequest(request());
        byte[] boundary = java.util.Arrays.copyOf(message, 4096);
        java.util.Arrays.fill(boundary, message.length, boundary.length, (byte) ' ');
        assertThat(service.bootstrap(new ByteArrayInputStream(boundary)).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void zeroLengthReadsCannotBypassProgressChecksOrLoseBytes() {
        var actual = new ByteArrayInputStream(codec.writeBootstrapRequest(request()));
        InputStream zero = new InputStream() {
            @Override
            public int read(byte[] bytes, int offset, int length) {
                return 0;
            }

            @Override
            public int read() {
                return actual.read();
            }
        };
        assertThat(service.bootstrap(zero).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void zeroLengthReadThenEofIsStillInvalidJson() {
        InputStream zero = new InputStream() {
            @Override
            public int read(byte[] bytes, int offset, int length) {
                return 0;
            }

            @Override
            public int read() {
                return -1;
            }
        };
        assertError(service.bootstrap(zero), RuntimeErrorCode.INVALID_REQUEST);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void transportReadFailureDoesNotExposeItsMessageOrStartStateAccess() {
        InputStream failure = new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                throw new java.io.IOException("synthetic-private-upstream-body");
            }
        };
        assertError(service.bootstrap(failure), RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void uncertainKernelFailureCannotBeReportedAsDefinitelyUnsent() {
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenThrow(new IllegalStateException("synthetic-private-upstream-body"));
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @Test
    void missingBodyFailsClosedBeforeStateAccess() {
        assertError(service.bootstrap(null), RuntimeErrorCode.INVALID_REQUEST);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void unsupportedVersionIsAControlledError() {
        String json = "{\"protocolVersion\":2,\"runId\":\"" + RUN + "\",\"attemptId\":\"" + attempt.attemptId()
                + "\",\"podUid\":\"" + POD + "\"}";
        assertError(service.bootstrap(new ByteArrayInputStream(json.getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                RuntimeErrorCode.UNSUPPORTED_VERSION);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void excessiveJsonDepthIsAControlledLimitErrorBeforeUnknownFieldMapping() {
        String json = "{\"unknown\":" + "[".repeat(33) + "0" + "]".repeat(33) + "}";
        assertError(service.bootstrap(new ByteArrayInputStream(json.getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                RuntimeErrorCode.LIMIT_EXCEEDED);
        verifyNoInteractions(kernel, auth);
    }

    @Test
    void staleAttemptCannotReachCurrentActorOrTransition() {
        var request = new BootstrapRequest(1, RUN, UUID.randomUUID(), POD);
        assertError(service.bootstrap(new ByteArrayInputStream(codec.writeBootstrapRequest(request))),
                RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void closedObservedWorkloadCannotReachCurrentActorOrTransition() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.CLOSED, Optional.empty())));
        assertError(service.bootstrap(body()), RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void heartbeatRequiresAnAlreadyStoredClaim() {
        var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, CLAIM_ID, 9);
        assertError(
                service
                        .heartbeat(new ByteArrayInputStream(
                                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2)))),
                RuntimeErrorCode.STALE_BINDING);
        verifyNoInteractions(auth);
        verify(kernel, never()).heartbeat(any(), anyLong(), any(AiRuntimeOperationBudget.class));
    }

    @ParameterizedTest
    @EnumSource(value = Status.class, names = {"DENIED", "LOSER", "LIMIT_REACHED"})
    void rejectedKernelStatusesHaveClosedProtocolCodes(Status status) {
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.empty(status));
        assertError(service.bootstrap(body()),
                status == Status.LIMIT_REACHED ? RuntimeErrorCode.LIMIT_EXCEEDED : RuntimeErrorCode.DENIED);
    }

    @Test
    void handledFailuresLogOnlyControlledFieldsAndMatchingCorrelation() throws IOException {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(AiRuntimeRunnerServiceImpl.class);
        var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        var level = logger.getLevel();
        boolean additive = logger.isAdditive();
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        logger.setAdditive(false);
        events.start();
        logger.addAppender(events);
        try {
            String canary = "synthetic-private-upstream-body";
            ResponseEntity<byte[]> invalid;
            try (var input = new ByteArrayInputStream(("{\"private\":\"" + canary + "\",\"actorId\":\"" + ACTOR + "\"}")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                invalid = service.bootstrap(input);
            }
            when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any()))
                    .thenThrow(new IllegalStateException(canary + ACTOR));
            var unavailable = service.bootstrap(body());
            when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenReturn(actor(ACTOR));
            when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                    .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
            when(kernel.heartbeat(eq(claim.binding()), eq(2L), any(AiRuntimeOperationBudget.class)))
                    .thenThrow(new IllegalStateException(canary + POD));
            var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, CLAIM_ID, 9);
            ResponseEntity<byte[]> unknown;
            try (var input = new ByteArrayInputStream(
                    codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2)))) {
                unknown = service.heartbeat(input);
            }
            var responses = List.of(invalid, unavailable, unknown);
            var codes = List
                    .of(RuntimeErrorCode.INVALID_REQUEST, RuntimeErrorCode.UNAVAILABLE,
                            RuntimeErrorCode.UNKNOWN_OUTCOME);
            assertThat(events.list).hasSize(3);
            for (int i = 0; i < responses.size(); i++) {
                var error = codec.readRuntimeError(responses.get(i).getBody());
                var event = events.list.get(i);
                assertThat(error.code()).isEqualTo(codes.get(i));
                assertThat(event.getArgumentArray())
                        .containsExactly(i == 2 ? "heartbeat" : "bootstrap", error.code().name(),
                                error.correlationId());
                assertThat(event.getMessage()).isEqualTo("AI runner operation={} code={} correlation={}");
                assertThat(event.getLevel())
                        .isEqualTo(i == 0 ? ch.qos.logback.classic.Level.DEBUG : ch.qos.logback.classic.Level.WARN);
                assertThat(event.getThrowableProxy()).isNull();
                assertThat(event.getFormattedMessage())
                        .doesNotContain(canary, ACTOR.toString(), RUN.toString(), POD.toString(), CLAIM_ID.toString(),
                                "private", "actorId");
            }
        } finally {
            logger.detachAppender(events);
            events.stop();
            logger.setLevel(level);
            logger.setAdditive(additive);
        }
    }

    @Test
    void unknownAndForeignLaunchHaveIdenticalPreAuthorizationDenial() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class))).thenReturn(Optional.empty());
        var unknown = service.bootstrap(body());
        RunSnapshot known = snapshot(WorkloadState.REGISTERED, Optional.empty());
        var original = known.attempt().spec();
        var launch = original.launch();
        var foreign = new LaunchSpec("foreign-cluster", launch.namespaceName(), launch.namespaceUid(),
                launch.serviceAccountName(), launch.serviceAccountUid(), launch.templateDigest(),
                launch.runtimeClass());
        var foreignAttempt = new AttemptSpec(original.attemptId(), original.launchDeadline(), original.maxDeadline(),
                original.imageDigest(), original.profileRevision(), original.securityRevision(),
                original.trustRevision(), original.protocol(), foreign);
        var current = new AttemptSnapshot(foreignAttempt, 1, AttemptState.LAUNCHING, 9, Optional.empty(),
                Optional.empty(), 2, NOW, NOW);
        var foreignLaunch = new LaunchSnapshot(foreign, "job-one", Optional.of("job-uid"), 1, CleanupState.NONE, NOW,
                NOW);
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional
                        .of(new RunSnapshot(known.spec(), known.state(), 7, 9, 1, current, foreignLaunch,
                                known.workloads(), 2, NOW, NOW)));
        var denied = service.bootstrap(body());
        assertError(unknown, RuntimeErrorCode.UNAVAILABLE);
        assertError(denied, RuntimeErrorCode.UNAVAILABLE);
        assertThat(unknown.getStatusCode()).isEqualTo(denied.getStatusCode());
        assertThat(codec.readRuntimeError(unknown.getBody()).code())
                .isEqualTo(codec.readRuntimeError(denied.getBody()).code());
        verifyNoInteractions(auth);
        verify(kernel, never()).bootstrap(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void unencodableHeartbeatResultAfterTransitionIsUnknownOutcome() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
        // Sequence0 is a valid internal initial claim, but cannot encode a heartbeat acknowledgment.
        when(kernel.heartbeat(eq(claim.binding()), eq(2L), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Transition.value(Status.APPLIED, new Claim(claim.binding(), NOW.plusSeconds(7), 0)));
        var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, CLAIM_ID, 9);
        assertError(
                service
                        .heartbeat(new ByteArrayInputStream(
                                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2)))),
                RuntimeErrorCode.UNKNOWN_OUTCOME);
        verify(kernel).heartbeat(eq(claim.binding()), eq(2L), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void heartbeatRequestBudgetExhaustionDoesNotReportTerminalLeaseExpiry() {
        when(kernel.snapshot(eq(RUN), any(AiRuntimeOperationBudget.class)))
                .thenReturn(Optional.of(snapshot(WorkloadState.REGISTERED, Optional.of(claim))));
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> {
            nanos.addAndGet(Duration.ofSeconds(5).toNanos());
            return actor(ACTOR);
        });
        var wire = new com.otilm.ai.runtime.protocol.ClaimBinding(RUN, attempt.attemptId(), POD, CLAIM_ID, 9);
        assertError(
                service
                        .heartbeat(new ByteArrayInputStream(
                                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, wire, 2)))),
                RuntimeErrorCode.UNAVAILABLE);
        verify(kernel, never()).heartbeat(any(), anyLong(), any(AiRuntimeOperationBudget.class));
        verify(kernel, never()).expire(any());
    }

    @Test
    void bodyAndActorElapsedTimeReachesBoundedKernelWithoutReset() {
        var first = new java.util.concurrent.atomic.AtomicBoolean(true);
        InputStream slowBody = new ByteArrayInputStream(codec.writeBootstrapRequest(request())) {
            @Override
            public synchronized int read(byte[] bytes, int offset, int length) {
                int read = super.read(bytes, offset, length);
                if (first.getAndSet(false)) {
                    nanos.addAndGet(Duration.ofSeconds(2).toNanos());
                }
                return read;
            }
        };
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(invocation -> {
            assertThat((Duration) invocation.getArgument(1)).isEqualTo(Duration.ofSeconds(3));
            nanos.addAndGet(Duration.ofSeconds(2).toNanos());
            return actor(ACTOR);
        });
        when(kernel.bootstrap(eq(expected), eq(ref), any(AiRuntimeOperationBudget.class))).thenAnswer(invocation -> {
            var passed = invocation.getArgument(2, AiRuntimeOperationBudget.class);
            assertThat(passed.remaining()).isEqualTo(Duration.ofSeconds(1));
            return Transition.value(Status.APPLIED, claim);
        });
        assertThat(service.bootstrap(slowBody).getStatusCode().value()).isEqualTo(200);
    }

    private BootstrapRequest request() {
        return new BootstrapRequest(1, RUN, attempt.attemptId(), POD);
    }

    private InputStream body() {
        return new ByteArrayInputStream(codec.writeBootstrapRequest(request()));
    }

    private static AuthenticationInfo actor(UUID id) {
        return new AuthenticationInfo(AuthMethod.USER_PROXY, id.toString(), "synthetic-actor", List.of(), "{}");
    }

    private void assertError(ResponseEntity<byte[]> response, RuntimeErrorCode code) {
        assertThat(response.getStatusCode().isError()).isTrue();
        var error = codec.readRuntimeError(response.getBody());
        assertThat(error.code()).isEqualTo(code);
        assertThat(error.correlationId()).isNotNull();
        assertThat(new String(response.getBody(), java.nio.charset.StandardCharsets.UTF_8))
                .doesNotContain("synthetic-private-upstream-body", "exception", "stackTrace");
    }

    private RunSnapshot snapshot(WorkloadState state, Optional<Claim> currentClaim) {
        var spec = new RunSpec(RUN, Optional.empty(), ACTOR, "synthetic", 2, 2, 5, NOW.plusSeconds(120));
        var current = new AttemptSnapshot(attempt, 1,
                currentClaim.isPresent() ? AttemptState.CLAIMED : AttemptState.LAUNCHING, 9, Optional.empty(),
                currentClaim, 2, NOW, NOW);
        var launch = new LaunchSnapshot(attempt.launch(), "job-one", Optional.of("job-uid"), 1, CleanupState.NONE, NOW,
                NOW);
        var workload = new WorkloadSnapshot(ref, "pod-one", "job-uid", state, 1, NOW.plusSeconds(30), Optional.empty(),
                Optional.empty(), 0, Optional.empty(), NOW, NOW);
        return new RunSnapshot(spec, RunState.RUNNING, 7, 9, 1, current, launch, List.of(workload), 2, NOW, NOW);
    }
}
