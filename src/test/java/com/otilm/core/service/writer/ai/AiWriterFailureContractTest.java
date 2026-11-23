package com.otilm.core.service.writer.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementSessionRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.util.AiRuntimeFixture;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Real writer refusal paths over mocked persistence; transaction rollback remains an integration concern. */
@ExtendWith(MockitoExtension.class)
class AiWriterFailureContractTest {
    @Mock
    private AiRuntimeRepository runtime;
    @Mock
    private AiModelDispatchRepository models;
    @Mock
    private AiModelManagementSessionRepository sessions;

    @Test
    void returnsSafeDomainMessage_whenReservedDispatchCannotPersistItsIntent() {
        // given
        var at = Instant.parse("2030-01-01T00:00:00Z");
        var connection = new ConnectionVersion(UUID.randomUUID(), 1, 1, 1, "test-model");
        var payload = AiModelDispatchPayload.text("test-model", 32, "Core probe", "Reply OK", "");
        var request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), ManagementAction.CONNECTION_CHECK, connection, payload, 32, at.plusSeconds(60));
        var writer = new AiModelDispatchWriter(runtime, models);
        var budget = AiRuntimeOperationBudget.start();
        when(runtime.decisionTime()).thenReturn(at);
        when(models.lockConnection(connection.id())).thenReturn(Optional.of(connection.id()));
        when(models.lockManagementSession(request.sessionId())).thenReturn(Optional.of(request.sessionId()));
        when(models.managementPreparationCurrent(any(), any())).thenReturn(true);
        when(models.reserveManagement(any(), any())).thenReturn(1);

        // when
        ThrowingCallable prepareDispatch = () -> writer.prepareManagement(request, budget);

        // then
        assertThatThrownBy(prepareDispatch)
                .isInstanceOfSatisfying(AiModelDispatchWriter.Rejected.class,
                        failure -> assertThat(PlatformException.safeMessage(failure, "fallback"))
                                .isEqualTo("Model dispatch conflict"))
                .hasNoCause();
        verify(models).insertManagementIntent(any(), any());
    }

    @Test
    void returnsSafeDomainMessage_whenInsertedManagementSessionHasNoMetadata() {
        // given
        var at = Instant.parse("2030-01-01T00:00:00Z");
        var connection = new ConnectionVersion(UUID.randomUUID(), 1, 1, 1, "test-model");
        var spec = new Spec(UUID.randomUUID(), UUID.randomUUID(), connection, ManagementAction.CONNECTION_CHECK,
                at.plusSeconds(60), 1, 32);
        var writer = new AiModelManagementSessionWriter(runtime, models, sessions);
        var budget = AiRuntimeOperationBudget.start();
        when(runtime.decisionTime()).thenReturn(at);
        when(models.lockConnection(connection.id())).thenReturn(Optional.of(connection.id()));
        when(sessions.modelCurrent(any(), any())).thenReturn(true);
        when(sessions.insert(any(), any())).thenReturn(1);

        // when
        ThrowingCallable createSession = () -> writer.create(spec, budget);

        // then
        assertThatThrownBy(createSession)
                .isInstanceOfSatisfying(RuntimeException.class,
                        failure -> assertThat(PlatformException.safeMessage(failure, "fallback"))
                                .isEqualTo("Management session conflict"))
                .hasNoCause();
        verify(sessions).metadata(any(), any());
    }

    @Test
    void returnsSafeDomainMessage_whenRuntimeCreationHasNoCurrentControl() {
        // given
        var at = Instant.parse("2030-01-01T00:00:00Z");
        var run = AiRuntimeFixture.run(at);
        var attempt = AiRuntimeFixture.attempt(at);
        var writer = new AiRuntimeWriter(runtime);
        var causeCanary = "SYNTHETIC_CAUSE_SECRET_CANARY";

        // when
        ThrowingCallable createRun = () -> writer.create(new ControlVersion(1), run, attempt);

        // then
        assertThatThrownBy(createRun).isInstanceOfSatisfying(AiRuntimeWriter.Rejected.class, failure -> {
            failure.initCause(new IllegalStateException(causeCanary));
            assertThat(PlatformException.safeMessage(failure, "fallback"))
                    .isEqualTo("Runtime transition was not applied")
                    .doesNotContain(causeCanary);
        });
    }

    @Test
    void returnsFallback_whenAnInfrastructureFailureCarriesPrivateDetail() {
        // given
        var causeCanary = "SYNTHETIC_CAUSE_SECRET_CANARY";
        var infrastructureFailure = new IllegalStateException(causeCanary);

        // when
        String safeMessage = PlatformException.safeMessage(infrastructureFailure, "Operation unavailable");

        // then
        assertThat(safeMessage).isEqualTo("Operation unavailable").doesNotContain(causeCanary);
    }
}
