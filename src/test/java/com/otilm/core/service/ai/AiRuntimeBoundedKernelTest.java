package com.otilm.core.service.ai;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.transaction.TransactionSystemException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AiRuntimeBoundedKernelTest {
    private final AiRuntimeWriter writer = mock(AiRuntimeWriter.class);
    private final AiRuntimeKernel kernel = new AiRuntimeKernel(mock(AiRuntimeRepository.class), writer,
            new AiFeatureGate(true));
    private final WorkloadRef workload = new WorkloadRef("cluster-one", "pod-one");
    private final Expected expected = new Expected(UUID.randomUUID(), UUID.randomUUID(), 1, 1);
    private final ClaimBinding binding = new ClaimBinding(expected.runId(), expected.attemptId(), workload,
            UUID.randomUUID(), 1);
    private final AiRuntimeOperationBudget budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), () -> 0L);

    @Test
    void boundedPositivePreservesTheSameBudgetAndClaim() {
        var result = Transition.value(Status.APPLIED, new Claim(binding, Instant.parse("2026-11-04T12:00:00Z"), 0));
        when(writer.bootstrap(expected, workload, budget)).thenReturn(result);
        assertThat(kernel.bootstrap(expected, workload, budget)).isSameAs(result);
    }

    @Test
    void onlyDefiniteRejectedRollbackBecomesConflict() {
        when(writer.bootstrap(expected, workload, budget)).thenThrow(new AiRuntimeWriter.Rejected());
        assertThat(kernel.bootstrap(expected, workload, budget).status()).isEqualTo(Status.CONFLICT);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void boundedBootstrapDoesNotTurnStorageOrTransactionUncertaintyIntoConflict(boolean transaction) {
        RuntimeException failure = transaction
                ? new TransactionSystemException("synthetic-private-storage-error")
                : new DataAccessResourceFailureException("synthetic-private-storage-error");
        when(writer.bootstrap(expected, workload, budget)).thenThrow(failure);
        assertThatThrownBy(() -> kernel.bootstrap(expected, workload, budget)).isSameAs(failure);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void boundedHeartbeatDoesNotTurnStorageOrTransactionUncertaintyIntoConflict(boolean transaction) {
        RuntimeException failure = transaction
                ? new TransactionSystemException("synthetic-private-storage-error")
                : new DataAccessResourceFailureException("synthetic-private-storage-error");
        when(writer.heartbeat(binding, 2, budget)).thenThrow(failure);
        assertThatThrownBy(() -> kernel.heartbeat(binding, 2, budget)).isSameAs(failure);
    }

    @Test
    void oldTrustedInternalApiKeepsItsExistingConflictCompatibility() {
        when(writer.bootstrap(expected, workload)).thenThrow(new TransactionSystemException("synthetic-private-error"));
        assertThat(kernel.bootstrap(expected, workload).status()).isEqualTo(Status.CONFLICT);
    }
}
