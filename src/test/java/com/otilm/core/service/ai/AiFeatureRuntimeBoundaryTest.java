package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.security.ai.AiRuntimeControllerAuthority;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter;
import java.io.InputStream;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;

/** Feature-policy controls with mocked infrastructure; no deployed identity or sandbox acceptance. */
@ExtendWith(MockitoExtension.class)
class AiFeatureRuntimeBoundaryTest {
    @Mock
    private AiRuntimeKernel kernel;
    @Mock
    private PlatformAuthenticationClient auth;
    @Mock
    private AiRuntimeCleanupWriter cleanup;
    @Mock
    private ObjectProvider<AiRuntimeControllerAuthority> controllers;
    @Mock
    private ObjectProvider<AiRuntimeControllerServiceImpl.Source> sources;
    @Mock
    private AiRuntimeGatewayAuthority runAuthority;
    @Mock
    private AiRuntimeManagementGatewayAuthority managementAuthority;
    @Mock
    private AiModelRunDispatchService runDispatch;
    @Mock
    private AiModelManagementDispatchService managementDispatch;
    @Mock
    private AiModelRunOutcomeWriter runOutcomes;
    @Mock
    private AiModelManagementOutcomeWriter managementOutcomes;
    @Mock
    private AiModelManagementGatewayWriter assignments;

    @ParameterizedTest
    @EnumSource(Operation.class)
    void deniesNewRuntimeOperationBeforeBodyOrEffects_whenFeatureIsDisabled(Operation operation) throws Exception {
        // given
        var feature = new AiFeatureGate(false);
        var runner = new AiRuntimeRunnerServiceImpl(kernel, auth, feature);
        var controller = new AiRuntimeControllerServiceImpl(kernel, cleanup, controllers, sources, feature);
        var runGateway = new AiRuntimeGatewayServiceImpl(runAuthority, runDispatch, runOutcomes, feature);
        var managementGateway = new AiRuntimeManagementGatewayServiceImpl(managementAuthority, managementDispatch,
                assignments, managementOutcomes, feature);
        var subject = new RuntimeProxyCertificateClaims("cluster-one", "runtime", "worker", "worker-one",
                UUID.randomUUID());
        RuntimePeerRole role = switch (operation) {
            case RUNNER_BOOTSTRAP, RUNNER_HEARTBEAT -> RuntimePeerRole.RUNNER_PROXY;
            case RUN_REDEEM -> RuntimePeerRole.GATEWAY_RUN;
            case MANAGEMENT_REDEEM -> RuntimePeerRole.GATEWAY_MANAGEMENT;
            default -> RuntimePeerRole.CONTROLLER;
        };
        InputStream unread = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("Disabled AI operation read its request body");
            }
        };
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentPeer).thenReturn(Optional.of(subject));
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(new RuntimePeer(role, subject)));

            // when
            ResponseEntity<byte[]> response = switch (operation) {
                case RUNNER_BOOTSTRAP -> runner.bootstrap(unread);
                case RUNNER_HEARTBEAT -> runner.heartbeat(unread);
                case CONTROLLER_RECONCILE -> controller.reconcile(unread);
                case CONTROLLER_REGISTER -> controller.register(unread);
                case RUN_REDEEM -> runGateway.redeem(unread);
                case MANAGEMENT_REDEEM -> managementGateway.redeem(unread);
            };

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(403);
            assertThat(new ProtocolCodec().readRuntimeError(response.getBody()).code())
                    .isEqualTo(RuntimeErrorCode.DENIED);
            transport.verifyNoInteractions();
            verifyNoInteractions(kernel, auth, cleanup, controllers, sources, runAuthority, managementAuthority,
                    runDispatch, managementDispatch, runOutcomes, managementOutcomes, assignments);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private enum Operation {
        RUNNER_BOOTSTRAP,
        RUNNER_HEARTBEAT,
        CONTROLLER_RECONCILE,
        CONTROLLER_REGISTER,
        RUN_REDEEM,
        MANAGEMENT_REDEEM
    }
}
