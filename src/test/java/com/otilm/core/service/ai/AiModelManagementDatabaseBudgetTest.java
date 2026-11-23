package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementOutcomeRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Persistence-boundary elapsed checks only, not a wall-clock or transaction rollback guarantee. */
class AiModelManagementDatabaseBudgetTest {
    @ParameterizedTest
    @CsvSource({
            "registry,submillis",
            "assignment,submillis",
            "outcome,submillis",
            "dispatch,submillis",
            "registry,after-config",
            "assignment,after-config",
            "outcome,after-config",
            "dispatch,after-config",
            "registry,after-sql",
            "assignment,after-sql",
            "outcome,after-sql",
            "dispatch,after-sql"})
    void everyPotentiallyBlockingQueryRejectsZeroTimeoutAndChecksBothSidesOfTheBoundary(String kind, String phase) {
        var runtime = mock(AiRuntimeRepository.class);
        var registry = mock(AiRuntimeManagementGatewayRepository.class);
        var models = mock(AiModelDispatchRepository.class);
        var assignments = mock(AiModelManagementGatewayRepository.class);
        var outcomes = mock(AiModelManagementOutcomeRepository.class);
        var clock = new AtomicLong();
        var budget = AiRuntimeOperationBudget
                .start(phase.equals("submillis") ? Duration.ofNanos(500000) : Duration.ofSeconds(5), clock::get);
        when(runtime.configureTransaction(anyLong())).thenAnswer(call -> {
            if (phase.equals("after-config")) {
                clock.set(5_000_000_000L);
            }
            return "bounded";
        });
        when(runtime.decisionTime()).thenAnswer(call -> {
            if (phase.equals("after-sql")) {
                clock.set(5_000_000_000L);
            }
            return Instant.parse("2030-01-01T00:00:00Z");
        });
        when(registry.revision()).thenAnswer(call -> {
            if (phase.equals("after-sql")) {
                clock.set(5_000_000_000L);
            }
            return Optional.of(0L);
        });
        when(models.lockManagementDeployment()).thenAnswer(call -> {
            if (phase.equals("after-sql")) {
                clock.set(5_000_000_000L);
            }
            return Optional.of(1L);
        });
        UUID id = UUID.randomUUID();
        var peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT,
                new RuntimeProxyCertificateClaims("cluster", "proof", "management", "pod", UUID.randomUUID()));
        var connection = new ConnectionVersion(UUID.randomUUID(), 1, 1, 1, "lab");
        var q = new ManagementRedemption(id, id, id, ManagementAction.CONNECTION_CHECK, connection, "a".repeat(64),
                Instant.parse("2030-01-01T00:00:00Z"), id);
        var registryWriter = new AiRuntimeManagementGatewayWriter(runtime, registry);
        var assignmentWriter = new AiModelManagementGatewayWriter(runtime, registry, assignments);
        var outcomeWriter = new AiModelManagementOutcomeWriter(runtime, registry, assignments, outcomes);
        var dispatchWriter = new AiModelDispatchWriter(runtime, models);
        assertThatThrownBy(() -> {
            switch (kind) {
                case "registry" -> registryWriter.revision(budget);
                case "assignment" -> assignmentWriter.requireAssigned(id, peer, budget);
                case "outcome" -> outcomeWriter.read(id, id, id, budget);
                case "dispatch" -> dispatchWriter.consumeManagement(q, id, peer, budget);
                default -> throw new AssertionError();
            }
        }).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        if (phase.equals("submillis")) {
            verifyNoInteractions(runtime, registry, models, assignments, outcomes);
        } else {
            verify(runtime).configureTransaction(longThat(millis -> millis >= 1 && millis <= 5000));
        }
        verify(assignments, never()).assign(any(), anyString(), any(), any());
        verify(outcomes, never()).append(any(), any(), anyString(), any(), any());
        verify(models, never()).consumeAssignedManagementIntent(any(), any(), anyString(), any(), any());
    }
}
