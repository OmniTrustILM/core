package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.model.ai.AiRuntimeGatewayState;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Actual closed HTTP operation logic over typed registry boundaries; no native or database attestation. */
class AiRuntimeGatewayRegistrationStatusTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void absentCurrentRegistrationReturnsOnlyOwnRolePendingWithoutConsumingAnything(boolean management)
            throws Exception {
        var fixture = new Fixture();
        try (var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.peer(management)));
            when(fixture.runRegistrations.current(any(), any())).thenReturn(Optional.empty());
            when(fixture.managementRegistrations.current(any(), any())).thenReturn(Optional.empty());
            var reply = fixture.registration(management);
            fixture.noBusinessEffects();
            assertThat(reply.getStatusCode().value()).isEqualTo(200);
            var body = new ObjectMapper().readTree(reply.getBody());
            assertThat(body.size()).isEqualTo(2);
            assertThat(body.path("version").intValue()).isEqualTo(1);
            assertThat(body.path("kind").textValue())
                    .isEqualTo(management
                            ? "management-gateway-registration-pending"
                            : "run-gateway-registration-pending");
            fixture.noBusinessEffects();
            if (management) {
                verifyNoInteractions(fixture.runRegistrations);
            } else {
                verifyNoInteractions(fixture.managementRegistrations);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void onlyTypedCurrentOwnRoleRegistrationReturnsTheClosedReadyLabel(boolean management) throws Exception {
        var fixture = new Fixture();
        var peer = fixture.peer(management);
        Instant until = Instant.parse("2030-01-01T00:00:00Z");
        when(fixture.runRegistrations.current(any(), any()))
                .thenReturn(Optional
                        .of(new AiRuntimeGatewayState.Registration(RuntimePeerRole.GATEWAY_RUN, peer.subject(), 4, 8,
                                UUID.randomUUID(), until)));
        when(fixture.managementRegistrations.current(any(), any()))
                .thenReturn(Optional
                        .of(new AiRuntimeManagementGatewayState.Registration(peer.subject(), 12, 6, UUID.randomUUID(),
                                until)));
        try (var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            var reply = fixture.registration(management);
            fixture.noBusinessEffects();
            assertThat(reply.getStatusCode().value()).isEqualTo(200);
            var body = new ObjectMapper().readTree(reply.getBody());
            assertThat(body.size()).isEqualTo(2);
            assertThat(body.path("kind").textValue())
                    .isEqualTo(management ? "management-gateway-registration-ready" : "run-gateway-registration-ready");
            fixture.noBusinessEffects();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void storageUncertaintyCannotBeDowngradedToPendingOrLeakItsCause(boolean management) {
        var fixture = new Fixture();
        when(fixture.runRegistrations.current(any(), any()))
                .thenThrow(new IllegalStateException("SYNTHETIC_SQL_CANARY"));
        when(fixture.managementRegistrations.current(any(), any()))
                .thenThrow(new IllegalStateException("SYNTHETIC_SQL_CANARY"));
        try (var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.peer(management)));
            var reply = fixture.registration(management);
            assertThat(reply.getStatusCode().value()).isEqualTo(503);
            assertThat(new ProtocolCodec().readRuntimeError(reply.getBody()).code())
                    .isEqualTo(RuntimeErrorCode.UNAVAILABLE);
            assertThat(new String(reply.getBody(), java.nio.charset.StandardCharsets.UTF_8)).doesNotContain("CANARY");
            fixture.noBusinessEffects();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void oppositeOrAbsentNativePeerCannotReadEitherRegistry(boolean management) {
        var fixture = new Fixture();
        try (var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.peer(!management)));
            assertThat(fixture.registration(management).getStatusCode().value()).isEqualTo(403);
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.empty());
            assertThat(fixture.registration(management).getStatusCode().value()).isEqualTo(401);
            verifyNoInteractions(fixture.runRegistrations, fixture.managementRegistrations);
            fixture.noBusinessEffects();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void aRegistryReadThatSpendsTheOriginalBudgetCannotPublishPending(boolean management) {
        var fixture = new Fixture();
        when(fixture.runRegistrations.current(any(), any())).thenAnswer(call -> {
            fixture.nanos.set(5_000_000_000L);
            return Optional.empty();
        });
        when(fixture.managementRegistrations.current(any(), any())).thenAnswer(call -> {
            fixture.nanos.set(5_000_000_000L);
            return Optional.empty();
        });
        try (var transport = mockStatic(RuntimeProxyTransport.class)) {
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.peer(management)));
            assertThat(fixture.registration(management).getStatusCode().value()).isEqualTo(503);
            fixture.noBusinessEffects();
        }
    }

    private static final class Fixture {
        private final AtomicLong nanos = new AtomicLong();
        private final AiRuntimeGatewayRegistrationWriter runRegistrations = mock(
                AiRuntimeGatewayRegistrationWriter.class);
        private final AiRuntimeManagementGatewayWriter managementRegistrations = mock(
                AiRuntimeManagementGatewayWriter.class);
        private final AiModelRunDispatchService runDispatch = mock(AiModelRunDispatchService.class);
        private final AiModelManagementDispatchService managementDispatch = mock(
                AiModelManagementDispatchService.class);
        private final AiModelRunOutcomeWriter runOutcomes = mock(AiModelRunOutcomeWriter.class);
        private final AiModelManagementGatewayWriter assignments = mock(AiModelManagementGatewayWriter.class);
        private final AiModelManagementOutcomeWriter managementOutcomes = mock(AiModelManagementOutcomeWriter.class);
        private final AiRuntimeGatewayServiceImpl run = new AiRuntimeGatewayServiceImpl(
                new AiRuntimeGatewayAuthority(runRegistrations), runDispatch, runOutcomes, nanos::get,
                new AiFeatureGate(true));
        private final AiRuntimeManagementGatewayServiceImpl management = new AiRuntimeManagementGatewayServiceImpl(
                new AiRuntimeManagementGatewayAuthority(managementRegistrations), managementDispatch, assignments,
                managementOutcomes, nanos::get, new AiFeatureGate(true));

        private RuntimePeer peer(boolean management) {
            return new RuntimePeer(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN,
                    new RuntimeProxyCertificateClaims("lab", "runtime", "gateway", "gateway-one",
                            UUID.fromString("408419f6-39b8-4636-9c6f-a93a6a886bed")));
        }

        private ResponseEntity<byte[]> registration(boolean selectedManagement) {
            return selectedManagement ? management.registration() : run.registration();
        }

        private void noBusinessEffects() {
            verifyNoInteractions(runDispatch, managementDispatch, runOutcomes, assignments, managementOutcomes);
        }
    }
}
