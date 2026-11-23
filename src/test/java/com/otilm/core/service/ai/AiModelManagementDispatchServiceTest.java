package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Composition only; persistence and authoritative CONNECT boundary are mocked, not claimed as native acceptance. */
class AiModelManagementDispatchServiceTest {
    private final AiModelManagementSessionWriter sessions = mock(AiModelManagementSessionWriter.class);
    private final AiModelDispatchWriter writer = mock(AiModelDispatchWriter.class);
    private final AiModelManagementAuthorization auth = mock(AiModelManagementAuthorization.class);
    private final AiModelManagementDispatchService service = new AiModelManagementDispatchService(sessions, writer,
            auth, new AiFeatureGate(true));
    private final UUID session = UUID.randomUUID(), actor = UUID.randomUUID(), key = UUID.randomUUID(),
            intentId = UUID.randomUUID(), correlation = UUID.randomUUID();
    private final ConnectionVersion connection = new ConnectionVersion(UUID.randomUUID(), 1, 2, 3, "maintained-model");
    private final Instant expiry = Instant.parse("2030-01-01T00:00:00.123456Z");
    private final RuntimePeer peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT,
            new RuntimeProxyCertificateClaims("cluster", "proof", "management", "pod", UUID.randomUUID()));
    private Facts facts = state(ManagementAction.CONNECTION_CHECK);

    private Facts state(ManagementAction action) {
        return new Facts(session, actor, connection, action, expiry, 2, 64, 0, 0);
    }

    private AiRuntimeOperationBudget budget;

    @BeforeEach
    void setup() {
        budget = AiRuntimeOperationBudget.start();
        when(sessions.metadata(session, budget)).thenAnswer(call -> Optional.of(facts));
        when(writer.preparedManagementByKey(session, key, budget)).thenReturn(Optional.empty());
        when(writer.prepareManagement(any(), eq(actor), eq(budget)))
                .thenAnswer(call -> Transition
                        .value(Status.APPLIED, ((ManagementPreparation) call.getArgument(0)).intentId()));
    }

    @ParameterizedTest
    @EnumSource(ManagementAction.class)
    void coreOwnsFixedProbeAfterFreshStoredActorConnect(ManagementAction action) {
        facts = state(action);
        var result = service.prepare(session, key, budget);
        var request = ArgumentCaptor.forClass(ManagementPreparation.class);
        var order = inOrder(sessions, auth, writer);
        order.verify(sessions).metadata(session, budget);
        order.verify(auth).requireConnect(actor, connection.id(), budget);
        order.verify(writer).preparedManagementByKey(session, key, budget);
        order.verify(writer).prepareManagement(request.capture(), eq(actor), eq(budget));
        var q = request.getValue();
        assertThat(q.actorId()).isEqualTo(actor);
        assertThat(q.sessionId()).isEqualTo(session);
        assertThat(q.outputTokens()).isEqualTo(32);
        assertThat(q.action()).isEqualTo(action);
        assertThat(AiModelDispatchPayload.hasModelAndOutputLimit(q.payload(), 32, connection.modelIdentifier()))
                .isTrue();
        assertThat(new String(q.payload().bytes(), java.nio.charset.StandardCharsets.UTF_8))
                .doesNotContain(actor.toString(), session.toString(), "credential");
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(result.value().orElseThrow().binding()).isEqualTo(binding(action));
    }

    @Test
    void returnsSafeDomainMessage_whenManagementWriterFailsWithPrivateDetail() {
        // given
        var providerCanary = "SYNTHETIC_PROVIDER_SECRET_CANARY";
        when(writer.prepareManagement(any(), eq(actor), eq(budget)))
                .thenThrow(new IllegalStateException(providerCanary));

        // when
        ThrowingCallable prepareManagement = () -> service.prepare(session, key, budget);

        // then
        assertThatThrownBy(prepareManagement)
                .isInstanceOfSatisfying(AiModelManagementDispatchService.Failure.class, failure -> {
                    assertThat(PlatformException.safeMessage(failure, "fallback"))
                            .isEqualTo("Management operation unavailable")
                            .doesNotContain(providerCanary);
                    assertThat(failure.code()).isEqualTo(RuntimeErrorCode.UNKNOWN_OUTCOME);
                })
                .hasNoCause();
    }

    @Test
    void replayUsesStoredExactBytesAndExpiryAfterFreshConnect() {
        var stored = intent();
        when(writer.preparedManagementByKey(session, key, budget)).thenReturn(Optional.of(stored));
        service.prepare(session, key, budget);
        var q = ArgumentCaptor.forClass(ManagementPreparation.class);
        verify(writer).prepareManagement(q.capture(), eq(actor), eq(budget));
        assertThat(q.getValue().intentId()).isEqualTo(intentId);
        assertThat(q.getValue().payload()).isEqualTo(stored.payload());
        verify(auth).requireConnect(actor, connection.id(), budget);
    }

    @Test
    void authorizationLossNeverReadsIntentPayloadOrCallsWriter() {
        doThrow(new AccessDeniedException("SYNTHETIC_CANARY"))
                .when(auth)
                .requireConnect(actor, connection.id(), budget);
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class)
                .extracting(f -> ((AiModelManagementDispatchService.Failure) f).code())
                .isEqualTo(RuntimeErrorCode.DENIED);
        verifyNoInteractions(writer);
    }

    @Test
    void missingSessionNeverCallsAuthOrWriter() {
        when(sessions.metadata(session, budget)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class);
        verifyNoInteractions(auth, writer);
    }

    @Test
    void nativeConsumePassesActualPeerAndFreshStoredActorToFinalWriter() {
        var stored = intent();
        when(writer.preparedManagementById(session, intentId, budget)).thenReturn(Optional.of(stored));
        var resolved = new ResolvedDispatch(intentId, connection, stored.payload(), 32,
                URI.create("https://model.invalid"), "finite-model", expiry, correlation);
        when(writer.consumeManagement(any(), eq(actor), eq(peer), eq(budget))).thenReturn(Optional.of(resolved));
        assertThat(service.consume(envelope(), correlation, peer, budget)).contains(resolved);
        var order = inOrder(sessions, auth, writer);
        order.verify(sessions).metadata(session, budget);
        order.verify(auth).requireConnect(actor, connection.id(), budget);
        order.verify(writer).preparedManagementById(session, intentId, budget);
        order.verify(writer).consumeManagement(any(), eq(actor), eq(peer), eq(budget));
    }

    @ParameterizedTest
    @EnumSource(value = RuntimePeerRole.class, names = "GATEWAY_MANAGEMENT", mode = EnumSource.Mode.EXCLUDE)
    void otherNativeAudienceDeniedBeforeSessionOrAuth(RuntimePeerRole role) {
        var wrong = new RuntimePeer(role, peer.subject());
        assertThatThrownBy(() -> service.consume(envelope(), correlation, wrong, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class);
        verifyNoInteractions(sessions, auth, writer);
    }

    @Test
    void postWriterFailureIsUnknownAndNeverLeaksCanary() {
        when(writer.prepareManagement(any(), eq(actor), eq(budget)))
                .thenThrow(new IllegalStateException("SYNTHETIC_CANARY"));
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class)
                .hasNoCause()
                .hasMessageNotContaining("CANARY")
                .extracting(f -> ((AiModelManagementDispatchService.Failure) f).code())
                .isEqualTo(RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @Test
    void foreignBindingNeverReachesWriter() {
        var foreign = new ManagementDispatchEnvelope(1, intentId, intent().payload().sha256(),
                new ManagementBinding(UUID.randomUUID(), session, connection.id(), 1, facts.action(), expiry));
        assertThatThrownBy(() -> service.consume(foreign, correlation, peer, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class);
        verifyNoInteractions(writer);
    }

    @org.junit.jupiter.api.AfterEach
    void clearSyntheticInterrupt() {
        Thread.interrupted();
    }

    @Test
    void actualLocalBudgetExhaustionDuringConnectIsUnavailableAndNeverReadsPayload() {
        var clock = new java.util.concurrent.atomic.AtomicLong();
        budget = AiRuntimeOperationBudget.start(clock::get);
        when(sessions.metadata(session, budget)).thenReturn(Optional.of(facts));
        doAnswer(call -> {
            clock.set(5_000_000_000L);
            throw new AccessDeniedException("SYNTHETIC_AUTH_CANARY");
        }).when(auth).requireConnect(actor, connection.id(), budget);
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class)
                .hasNoCause()
                .extracting(f -> ((AiModelManagementDispatchService.Failure) f).code())
                .isEqualTo(RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(writer);
    }

    @Test
    void connectInterruptionPreservesThreadFlagAndNeverReadsPayload() {
        doAnswer(call -> {
            Thread.currentThread().interrupt();
            throw new AccessDeniedException("SYNTHETIC_AUTH_CANARY");
        }).when(auth).requireConnect(actor, connection.id(), budget);
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class)
                .extracting(f -> ((AiModelManagementDispatchService.Failure) f).code())
                .isEqualTo(RuntimeErrorCode.INTERRUPTED);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
        verifyNoInteractions(writer);
    }

    @Test
    void preWriterDatabaseFailureIsContentFreeUnavailable() {
        when(sessions.metadata(session, budget)).thenThrow(new IllegalStateException("SYNTHETIC_SQL_CANARY"));
        assertThatThrownBy(() -> service.prepare(session, key, budget))
                .isInstanceOf(AiModelManagementDispatchService.Failure.class)
                .hasNoCause()
                .hasMessageNotContaining("CANARY")
                .extracting(f -> ((AiModelManagementDispatchService.Failure) f).code())
                .isEqualTo(RuntimeErrorCode.UNAVAILABLE);
        verifyNoInteractions(auth, writer);
    }

    private ManagementBinding binding(ManagementAction action) {
        return new ManagementBinding(actor, session, connection.id(), 1, action, expiry);
    }

    private ManagementIntent intent() {
        return new ManagementIntent(intentId, actor, session, facts.action(), connection,
                AiModelDispatchPayload.text(connection.modelIdentifier(), 32, "Core finite probe", "Reply OK", ""), 32,
                expiry);
    }

    private ManagementDispatchEnvelope envelope() {
        return new ManagementDispatchEnvelope(1, intentId, intent().payload().sha256(), binding(facts.action()));
    }
}
