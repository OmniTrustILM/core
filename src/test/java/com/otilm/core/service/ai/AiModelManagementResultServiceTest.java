package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementOutcome.Receipt;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Reader composition; persistence/Auth mocks do not prove maintained Auth or native acceptance. */
class AiModelManagementResultServiceTest {
    private final AiModelManagementSessionWriter sessions = mock(AiModelManagementSessionWriter.class);
    private final AiModelManagementOutcomeWriter outcomes = mock(AiModelManagementOutcomeWriter.class);
    private final AiModelManagementAuthorization auth = mock(AiModelManagementAuthorization.class);
    private final AiModelManagementResultService reader = new AiModelManagementResultService(sessions, outcomes, auth);
    private final UUID session = UUID.randomUUID(), intent = UUID.randomUUID(), actor = UUID.randomUUID();
    private final ConnectionVersion model = new ConnectionVersion(UUID.randomUUID(), 1, 2, 3, "lab");
    private final AiRuntimeOperationBudget budget = AiRuntimeOperationBudget.start();
    private final Facts facts = new Facts(session, actor, model, ManagementAction.CAPABILITY_CHECK,
            Instant.parse("2030-01-01T00:00:00Z"), 2, 64, 1, 32);

    @Test
    void onlyFreshStoredActorConnectPrecedesProtectedResultRead() {
        var expected = new Result(new Receipt(intent, UUID.randomUUID(), "a".repeat(64), 1), "TEXT",
                "SYNTHETIC_RESULT_CANARY", "STOP", 1L, 1L, 2L);
        when(sessions.metadata(session, budget)).thenReturn(Optional.of(facts));
        when(outcomes.read(session, intent, actor, budget)).thenReturn(Optional.of(expected));
        assertThat(reader.read(session, intent, actor, budget)).contains(expected);
        var order = inOrder(sessions, auth, outcomes);
        order.verify(sessions).metadata(session, budget);
        order.verify(auth).requireConnect(actor, model.id(), budget);
        order.verify(outcomes).read(session, intent, actor, budget);
    }

    @Test
    void foreignActorCannotUseAnOwnedSessionAndNeverCallsAuthOrResultStorage() {
        when(sessions.metadata(session, budget)).thenReturn(Optional.of(facts));
        UUID foreign = UUID.randomUUID();
        assertThatThrownBy(() -> reader.read(session, intent, foreign, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        verifyNoInteractions(auth, outcomes);
    }

    @Test
    void revokedConnectNeverDisclosesResultOrRawStorageFailure() {
        when(sessions.metadata(session, budget)).thenReturn(Optional.of(facts));
        doThrow(new AccessDeniedException("SYNTHETIC_AUTH_CANARY"))
                .when(auth)
                .requireConnect(actor, model.id(), budget);
        assertThatThrownBy(() -> reader.read(session, intent, actor, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause()
                .hasMessageNotContaining("CANARY");
        verifyNoInteractions(outcomes);
    }

    @Test
    void missingOrClosedSessionCannotAuthorizeHistoryByItsIdentifier() {
        when(sessions.metadata(session, budget)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> reader.read(session, intent, actor, budget)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(auth, outcomes);
    }
}
