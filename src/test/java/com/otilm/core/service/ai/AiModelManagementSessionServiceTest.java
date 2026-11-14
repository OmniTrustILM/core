package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Request;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/** Boundary composition only; mocks supply neither maintained Auth nor native management authority. */
class AiModelManagementSessionServiceTest {
    private final AiModelManagementSessionWriter writer = mock(AiModelManagementSessionWriter.class);
    private final AiModelManagementAuthorization authority = mock(AiModelManagementAuthorization.class);
    private final AiModelManagementSessionService service = new AiModelManagementSessionService(writer, authority,
            new AiFeatureGate(true));
    private final UUID session = UUID.randomUUID();
    private final UUID actor = UUID.randomUUID();
    private final ConnectionVersion model = new ConnectionVersion(UUID.randomUUID(), 2, 3, 4, "lab");
    private final Request request = new Request(session, actor, model.id(), ManagementAction.CONNECTION_CHECK,
            Instant.parse("2030-01-01T00:00:00.123456Z"), 1, 32);

    @BeforeEach
    void currentMetadata() {
        when(writer.connection(eq(model.id()), any())).thenReturn(Optional.of(model));
    }

    @Test
    void resolvesActualVersionsAndFreshConnectBeforeShortWriterUsingOneBudget() {
        var budget = AiRuntimeOperationBudget.start();
        var facts = new Facts(session, actor, model, request.action(), request.expiresAt(), 1, 32, 0, 0);
        var result = Transition.value(Status.APPLIED, facts);
        when(writer.create(any(), eq(budget))).thenReturn(result);
        assertThat(service.begin(request, budget)).isSameAs(result);
        var spec = ArgumentCaptor.forClass(Spec.class);
        var order = inOrder(writer, authority);
        order.verify(writer).connection(model.id(), budget);
        order.verify(authority).requireConnect(actor, model.id(), budget);
        order.verify(writer).create(spec.capture(), eq(budget));
        assertThat(spec.getValue())
                .isEqualTo(new Spec(session, actor, model, request.action(), request.expiresAt(), 1, 32));
        verifyNoMoreInteractions(writer, authority);
    }

    @Test
    void unknownOrStaleModelStopsBeforeAuthorityOrSessionWrite() {
        when(writer.connection(eq(model.id()), any())).thenReturn(Optional.empty());
        var budget = AiRuntimeOperationBudget.start();
        assertThatThrownBy(() -> service.begin(request, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Management session authority unavailable")
                .hasNoCause();
        verify(writer).connection(model.id(), budget);
        verifyNoMoreInteractions(writer, authority);
    }

    @Test
    void actualAuthorityDenialStopsBeforeCreatingAnySession() {
        doThrow(new AccessDeniedException("synthetic-canary-authority-detail"))
                .when(authority)
                .requireConnect(eq(actor), eq(model.id()), any());
        var budget = AiRuntimeOperationBudget.start();
        assertThatThrownBy(() -> service.begin(request, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Management session authority unavailable")
                .hasNoCause();
        verify(writer).connection(model.id(), budget);
        verify(authority).requireConnect(actor, model.id(), budget);
        verifyNoMoreInteractions(writer, authority);
    }

    @Test
    void cancellationDuringAuthorityDoesNotStartDatabaseWrite() {
        doAnswer(call -> {
            Thread.currentThread().interrupt();
            return null;
        }).when(authority).requireConnect(eq(actor), eq(model.id()), any());
        var budget = AiRuntimeOperationBudget.start();
        try {
            assertThatThrownBy(() -> service.begin(request, budget))
                    .isInstanceOfSatisfying(AiRuntimeOperationBudget.Unavailable.class,
                            failure -> assertThat(failure.interrupted()).isTrue())
                    .hasNoCause();
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
            verify(writer).connection(model.id(), budget);
            verify(authority).requireConnect(actor, model.id(), budget);
            verifyNoMoreInteractions(writer, authority);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void metadataPersistenceFailureIsNotRelabeledAsAnActorDenial() {
        var failure = new org.springframework.dao.DataAccessResourceFailureException("synthetic-db-failure-canary");
        var budget = AiRuntimeOperationBudget.start();
        when(writer.connection(model.id(), budget)).thenThrow(failure);
        assertThatThrownBy(() -> service.begin(request, budget)).isSameAs(failure);
        verify(writer).connection(model.id(), budget);
        verifyNoMoreInteractions(writer, authority);
    }

    @Test
    void exhaustedBudgetIsPreservedBeforeAnyMetadataOrAuthorityQuery() {
        var nanos = new java.util.concurrent.atomic.AtomicLong();
        var budget = AiRuntimeOperationBudget.start(nanos::get);
        nanos.set(java.time.Duration.ofSeconds(6).toNanos());
        assertThatThrownBy(() -> service.begin(request, budget))
                .isInstanceOfSatisfying(AiRuntimeOperationBudget.Unavailable.class,
                        failure -> assertThat(failure.interrupted()).isFalse())
                .hasNoCause();
        org.mockito.Mockito.verifyNoInteractions(writer, authority);
    }

    @Test
    void classAndMethodRetainMetadataOnlyTracingAndNoAmbientTransaction() throws Exception {
        assertThat(AiModelManagementSessionService.class.isAnnotationPresent(TraceMetadataOnly.class)).isTrue();
        var tx = AiModelManagementSessionService.class
                .getMethod("begin", Request.class, AiRuntimeOperationBudget.class)
                .getAnnotation(Transactional.class);
        assertThat(tx).isNotNull();
        assertThat(tx.propagation()).isEqualTo(Propagation.NOT_SUPPORTED);
    }
}
