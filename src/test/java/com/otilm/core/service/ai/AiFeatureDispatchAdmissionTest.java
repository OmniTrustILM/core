package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.security.ai.AiModelCertificateContext;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import java.time.Instant;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class AiFeatureDispatchAdmissionTest {
    @Mock
    private AiRuntimeKernel kernel;
    @Mock
    private AiModelRunInputWriter inputs;
    @Mock
    private AiModelDispatchWriter writer;
    @Mock
    private AiModelUseAuthorization models;
    @Mock
    private AiModelCertificateContext contexts;
    @Mock
    private AiModelManagementSessionWriter sessions;
    @Mock
    private AiModelManagementAuthorization managementAuthority;

    @ParameterizedTest
    @EnumSource(RunOperation.class)
    void deniesRunDispatchBeforeAnyRead_whenFeatureIsDisabled(RunOperation operation) {
        // given
        var service = new AiModelRunDispatchService(kernel, inputs, writer, models, contexts, new AiFeatureGate(false));
        var run = UUID.randomUUID();
        var attempt = UUID.randomUUID();
        var pod = UUID.randomUUID();
        var claimId = UUID.randomUUID();
        var claim = new ClaimBinding(run, attempt, new WorkloadRef("cluster-one", pod.toString()), claimId, 1);
        var envelope = new RunDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64),
                new RunBinding(run, attempt, pod, claimId, 1, Instant.parse("2030-01-01T00:00:00Z")));
        var correlation = UUID.randomUUID();
        var peer = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                "runtime", "gateway", "gateway-one", UUID.randomUUID()));
        var budget = AiRuntimeOperationBudget.start();

        // when
        ThrowingCallable dispatch = switch (operation) {
            case PREPARE -> () -> service.prepare(claim, correlation, budget);
            case CONSUME -> () -> service.consume(envelope, correlation, budget);
            case CONSUME_WITH_GATEWAY -> () -> service.consume(envelope, correlation, peer, budget);
        };

        // then
        assertThatThrownBy(dispatch)
                .isInstanceOfSatisfying(AiModelRunDispatchService.Failure.class,
                        failure -> assertThat(failure.code()).isEqualTo(RuntimeErrorCode.DENIED))
                .hasNoCause();
        verifyNoInteractions(kernel, inputs, writer, models, contexts);
    }

    @ParameterizedTest
    @EnumSource(ManagementOperation.class)
    void deniesManagementDispatchBeforeAnyRead_whenFeatureIsDisabled(ManagementOperation operation) {
        // given
        var service = new AiModelManagementDispatchService(sessions, writer, managementAuthority,
                new AiFeatureGate(false));
        var session = UUID.randomUUID();
        var correlation = UUID.randomUUID();
        var envelope = new ManagementDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64),
                new ManagementBinding(UUID.randomUUID(), session, UUID.randomUUID(), 1,
                        ManagementAction.CONNECTION_CHECK, Instant.parse("2030-01-01T00:00:00Z")));
        var peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, new RuntimeProxyCertificateClaims("cluster-one",
                "runtime", "gateway", "management-one", UUID.randomUUID()));
        var budget = AiRuntimeOperationBudget.start();

        // when
        ThrowingCallable dispatch = switch (operation) {
            case PREPARE -> () -> service.prepare(session, correlation, budget);
            case CONSUME -> () -> service.consume(envelope, correlation, peer, budget);
        };

        // then
        assertThatThrownBy(dispatch)
                .isInstanceOfSatisfying(AiModelManagementDispatchService.Failure.class,
                        failure -> assertThat(failure.code()).isEqualTo(RuntimeErrorCode.DENIED))
                .hasNoCause();
        verifyNoInteractions(sessions, writer, managementAuthority);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private enum RunOperation {
        PREPARE,
        CONSUME,
        CONSUME_WITH_GATEWAY
    }

    private enum ManagementOperation {
        PREPARE,
        CONSUME
    }
}
