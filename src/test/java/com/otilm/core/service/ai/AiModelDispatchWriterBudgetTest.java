package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Deterministic elapsed-clock controls; only persistence boundaries are mocked. */
class AiModelDispatchWriterBudgetTest {
    private final AiRuntimeRepository runtime = mock(AiRuntimeRepository.class);
    private final AiModelDispatchRepository model = mock(AiModelDispatchRepository.class);
    private final AiModelDispatchWriter writer = new AiModelDispatchWriter(runtime, model);
    private final AtomicLong nanos = new AtomicLong();
    private final ConnectionVersion connection = new ConnectionVersion(UUID.randomUUID(), 1, 1, 1, "lab");
    private final ManagementPreparation request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(),
            UUID.randomUUID(), UUID.randomUUID(), ManagementAction.CONNECTION_CHECK, connection,
            AiModelDispatchFixture.payload(32, "budget-canary"), 32, Instant.parse("2030-01-01T00:00:00Z"));

    @Test
    void positiveSubMillisecondBudgetDeniesBeforeDatabaseTimeoutCanBecomeZero() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofNanos(999_999), nanos::get);
        assertThatThrownBy(() -> writer.prepareManagement(request, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        verifyNoInteractions(runtime, model);
    }

    @Test
    void successfulSqlReturningAfterBudgetExpiryCannotProceedToNextLock() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(1), nanos::get);
        when(model.lockConnection(connection.id())).thenAnswer(call -> {
            nanos.set(Duration.ofSeconds(1).toNanos());
            return Optional.of(connection.id());
        });
        assertThatThrownBy(() -> writer.prepareManagement(request, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        verify(model, never()).lockManagementSession(request.sessionId());
    }

    @Test
    void timeoutConfigurationLeavingSubMillisecondBudgetCannotStartTheQuery() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(1), nanos::get);
        when(runtime.configureTransaction(anyLong())).thenAnswer(call -> {
            nanos.set(Duration.ofSeconds(1).toNanos() - 500_000);
            return "configured";
        });
        assertThatThrownBy(() -> writer.prepareManagement(request, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        verifyNoInteractions(model);
    }

    @Test
    void sqlTimeoutLeavesTimeForRollbackBeforeTheConnectionDeadline() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(800), nanos::get);
        writer.prepareManagement(request, budget);
        verify(runtime).configureTransaction(550);
    }

    @Test
    void timeoutConfigurationCannotSpendTheSqlCompletionReserve() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(1), nanos::get);
        when(runtime.configureTransaction(anyLong())).thenAnswer(call -> {
            nanos.set(Duration.ofMillis(800).toNanos());
            return "configured";
        });
        assertThatThrownBy(() -> writer.prepareManagement(request, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        verifyNoInteractions(model);
    }

}
