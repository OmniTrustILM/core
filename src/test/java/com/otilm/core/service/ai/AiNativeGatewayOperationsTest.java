package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;

/** Pure fixed-channel HTTP controls, not native identity acceptance. */
class AiNativeGatewayOperationsTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void oppositeEnvelopeKindIsRejectedBeforeAnyAssignmentOrBusinessRead(boolean management) throws Exception {
        var runAuthority = mock(AiRuntimeGatewayAuthority.class);
        var managementAuthority = mock(AiRuntimeManagementGatewayAuthority.class);
        var runDispatch = mock(AiModelRunDispatchService.class);
        var managementDispatch = mock(AiModelManagementDispatchService.class);
        var runOutcomes = mock(AiModelRunOutcomeWriter.class);
        var assignments = mock(AiModelManagementGatewayWriter.class);
        var outcomes = mock(AiModelManagementOutcomeWriter.class);
        var run = new AiRuntimeGatewayServiceImpl(runAuthority, runDispatch, runOutcomes, new AiFeatureGate(true));
        var mgt = new AiRuntimeManagementGatewayServiceImpl(managementAuthority, managementDispatch, assignments,
                outcomes, new AiFeatureGate(true));
        var expiry = Instant.parse("2030-01-01T00:00:00Z");
        var codec = new ProtocolCodec();
        com.otilm.ai.runtime.protocol.DispatchEnvelope envelope = management
                ? new RunDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64),
                        new RunBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1,
                                expiry))
                : new ManagementDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64),
                        new ManagementBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1,
                                ManagementAction.CONNECTION_CHECK, expiry));
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var document = json
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("gatewayCorrelation", UUID.randomUUID().toString());
        document.set("envelope", json.readTree(codec.writeDispatch(envelope)));
        var peer = new RuntimePeer(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN,
                new RuntimeProxyCertificateClaims("cluster", "proof", "gateway", "pod", UUID.randomUUID()));
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            var body = new ByteArrayInputStream(json.writeValueAsBytes(document));
            var response = management ? mgt.redeem(body) : run.redeem(body);
            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(codec.readRuntimeError(response.getBody()).code()).isEqualTo(RuntimeErrorCode.INVALID_REQUEST);
            verifyNoInteractions(runDispatch, managementDispatch, runOutcomes, assignments, outcomes);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unknownPreviousInvocationNeverPoisonsANewPreWriterDenial(boolean management) throws Exception {
        var runAuthority = mock(AiRuntimeGatewayAuthority.class);
        var managementAuthority = mock(AiRuntimeManagementGatewayAuthority.class);
        var runDispatch = mock(AiModelRunDispatchService.class);
        var managementDispatch = mock(AiModelManagementDispatchService.class);
        var runOutcomes = mock(AiModelRunOutcomeWriter.class);
        var assignments = mock(AiModelManagementGatewayWriter.class);
        var outcomes = mock(AiModelManagementOutcomeWriter.class);
        var run = new AiRuntimeGatewayServiceImpl(runAuthority, runDispatch, runOutcomes, new AiFeatureGate(true));
        var mgt = new AiRuntimeManagementGatewayServiceImpl(managementAuthority, managementDispatch, assignments,
                outcomes, new AiFeatureGate(true));
        var expiry = Instant.parse("2030-01-01T00:00:00Z");
        var codec = new ProtocolCodec();
        com.otilm.ai.runtime.protocol.DispatchEnvelope envelope = management
                ? new ManagementDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64),
                        new ManagementBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1,
                                ManagementAction.CONNECTION_CHECK, expiry))
                : new RunDispatchEnvelope(1, UUID.randomUUID(), "a".repeat(64), new RunBinding(UUID.randomUUID(),
                        UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1, expiry));
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var document = json
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("gatewayCorrelation", UUID.randomUUID().toString());
        document.set("envelope", json.readTree(codec.writeDispatch(envelope)));
        var peer = new RuntimePeer(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN,
                new RuntimeProxyCertificateClaims("cluster", "proof", "gateway", "pod", UUID.randomUUID()));
        org.mockito.Mockito
                .when(runDispatch
                        .consume(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException("SYNTHETIC_SQL_CANARY"));
        org.mockito.Mockito
                .when(managementDispatch
                        .consume(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException("SYNTHETIC_SQL_CANARY"));
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            var firstBody = new ByteArrayInputStream(json.writeValueAsBytes(document));
            var first = management ? mgt.redeem(firstBody) : run.redeem(firstBody);
            assertThat(codec.readRuntimeError(first.getBody()).code()).isEqualTo(RuntimeErrorCode.UNKNOWN_OUTCOME);
            org.mockito.Mockito
                    .when(runAuthority
                            .requireCurrent(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                    .thenThrow(new org.springframework.security.access.AccessDeniedException("SYNTHETIC_AUTH_CANARY"));
            org.mockito.Mockito
                    .when(managementAuthority
                            .requireCurrent(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                    .thenThrow(new org.springframework.security.access.AccessDeniedException("SYNTHETIC_AUTH_CANARY"));
            var untouched = new java.io.InputStream() {
                @Override
                public int read() {
                    throw new AssertionError("Pre-writer denial touched body");
                }
            };
            var second = management ? mgt.redeem(untouched) : run.redeem(untouched);
            assertThat(codec.readRuntimeError(second.getBody()).code()).isEqualTo(RuntimeErrorCode.DENIED);
        }
    }

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> emptyOutcomeStatuses() {
        return java.util.stream.Stream
                .of(false, true)
                .flatMap(management -> java.util.Arrays
                        .stream(com.otilm.core.model.ai.AiRuntimeState.Status.values())
                        .map(status -> org.junit.jupiter.params.provider.Arguments.of(management, status)));
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("emptyOutcomeStatuses")
    void onlyExplicitDeniedOrConflictMayBeDefiniteWithoutAnOutcomeReceipt(boolean management,
            com.otilm.core.model.ai.AiRuntimeState.Status status) throws Exception {
        var runOutcomes = mock(AiModelRunOutcomeWriter.class);
        var managementOutcomes = mock(AiModelManagementOutcomeWriter.class);
        var run = new AiRuntimeGatewayServiceImpl(mock(AiRuntimeGatewayAuthority.class),
                mock(AiModelRunDispatchService.class), runOutcomes, new AiFeatureGate(true));
        var mgt = new AiRuntimeManagementGatewayServiceImpl(mock(AiRuntimeManagementGatewayAuthority.class),
                mock(AiModelManagementDispatchService.class), mock(AiModelManagementGatewayWriter.class),
                managementOutcomes, new AiFeatureGate(true));
        org.mockito.Mockito
                .when(runOutcomes
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any()))
                .thenReturn(com.otilm.core.model.ai.AiRuntimeState.Transition.empty(status));
        org.mockito.Mockito
                .when(managementOutcomes
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any()))
                .thenReturn(com.otilm.core.model.ai.AiRuntimeState.Transition.empty(status));
        var peer = outcomePeer(management);
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            var body = new ByteArrayInputStream(outcomeBody(management, UUID.randomUUID(), UUID.randomUUID()));
            var response = management ? mgt.outcome(body) : run.outcome(body);
            var expected = status == com.otilm.core.model.ai.AiRuntimeState.Status.CONFLICT
                    ? RuntimeErrorCode.CONFLICT
                    : status == com.otilm.core.model.ai.AiRuntimeState.Status.DENIED
                            ? RuntimeErrorCode.DENIED
                            : RuntimeErrorCode.UNKNOWN_OUTCOME;
            assertThat(new ProtocolCodec().readRuntimeError(response.getBody()).code()).isEqualTo(expected);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void elapsedBudgetAfterOutcomeWriteCannotReturnAnAcknowledgement(boolean management) throws Exception {
        var nanos = new java.util.concurrent.atomic.AtomicLong();
        var runOutcomes = mock(AiModelRunOutcomeWriter.class);
        var managementOutcomes = mock(AiModelManagementOutcomeWriter.class);
        var run = new AiRuntimeGatewayServiceImpl(mock(AiRuntimeGatewayAuthority.class),
                mock(AiModelRunDispatchService.class), runOutcomes, nanos::get, new AiFeatureGate(true));
        var mgt = new AiRuntimeManagementGatewayServiceImpl(mock(AiRuntimeManagementGatewayAuthority.class),
                mock(AiModelManagementDispatchService.class), mock(AiModelManagementGatewayWriter.class),
                managementOutcomes, nanos::get, new AiFeatureGate(true));
        var intent = UUID.randomUUID();
        var correlation = UUID.randomUUID();
        byte[] bytes = outcomeBody(management, intent, correlation);
        String sha = management
                ? new AiRuntimeManagementWire().readOutcome(bytes).outcomeSha256()
                : new AiRuntimeGatewayWire().readOutcome(bytes).outcomeSha256();
        org.mockito.Mockito
                .when(runOutcomes
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any()))
                .thenAnswer(call -> {
                    nanos.set(5_000_000_000L);
                    return com.otilm.core.model.ai.AiRuntimeState.Transition
                            .value(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED,
                                    new com.otilm.core.model.ai.AiModelRunOutcome.Receipt(intent, correlation, sha, 1));
                });
        org.mockito.Mockito
                .when(managementOutcomes
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                org.mockito.ArgumentMatchers.any()))
                .thenAnswer(call -> {
                    nanos.set(5_000_000_000L);
                    return com.otilm.core.model.ai.AiRuntimeState.Transition
                            .value(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED,
                                    new com.otilm.core.model.ai.AiModelManagementOutcome.Receipt(intent, correlation,
                                            sha, 1));
                });
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(outcomePeer(management)));
            var body = new ByteArrayInputStream(bytes);
            var response = management ? mgt.outcome(body) : run.outcome(body);
            assertThat(response.getStatusCode().value()).isEqualTo(503);
            assertThat(nanos.get()).isEqualTo(5_000_000_000L);
            assertThat(new ProtocolCodec().readRuntimeError(response.getBody()).code())
                    .isEqualTo(RuntimeErrorCode.UNKNOWN_OUTCOME);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recordsOwnedOutcome_whenNewExecutionIsDisabled(boolean management) throws Exception {
        // given
        var runAuthority = mock(AiRuntimeGatewayAuthority.class);
        var managementAuthority = mock(AiRuntimeManagementGatewayAuthority.class);
        var runDispatch = mock(AiModelRunDispatchService.class);
        var managementDispatch = mock(AiModelManagementDispatchService.class);
        var runOutcomes = mock(AiModelRunOutcomeWriter.class);
        var managementOutcomes = mock(AiModelManagementOutcomeWriter.class);
        var assignments = mock(AiModelManagementGatewayWriter.class);
        var disabled = new AiFeatureGate(false);
        var run = new AiRuntimeGatewayServiceImpl(runAuthority, runDispatch, runOutcomes, disabled);
        var mgt = new AiRuntimeManagementGatewayServiceImpl(managementAuthority, managementDispatch, assignments,
                managementOutcomes, disabled);
        var intent = UUID.randomUUID();
        var correlation = UUID.randomUUID();
        byte[] bytes = outcomeBody(management, intent, correlation);
        String sha = java.util.HexFormat
                .of()
                .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
        if (management) {
            org.mockito.Mockito
                    .when(managementOutcomes
                            .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                    org.mockito.ArgumentMatchers.any()))
                    .thenReturn(com.otilm.core.model.ai.AiRuntimeState.Transition
                            .value(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED,
                                    new com.otilm.core.model.ai.AiModelManagementOutcome.Receipt(intent, correlation,
                                            sha, 1)));
        } else {
            org.mockito.Mockito
                    .when(runOutcomes
                            .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                                    org.mockito.ArgumentMatchers.any()))
                    .thenReturn(com.otilm.core.model.ai.AiRuntimeState.Transition
                            .value(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED,
                                    new com.otilm.core.model.ai.AiModelRunOutcome.Receipt(intent, correlation, sha,
                                            1)));
        }
        RuntimePeer peer = outcomePeer(management);
        try (MockedStatic<RuntimeProxyTransport> transport = mockStatic(RuntimeProxyTransport.class)) {
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));

            // when
            org.springframework.http.ResponseEntity<byte[]> response = management
                    ? mgt.outcome(new ByteArrayInputStream(bytes))
                    : run.outcome(new ByteArrayInputStream(bytes));

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            var acknowledgement = new com.fasterxml.jackson.databind.ObjectMapper().readTree(response.getBody());
            assertThat(acknowledgement.path("kind").asText())
                    .isEqualTo(management ? "management-outcome-recorded" : "run-outcome-recorded");
            assertThat(acknowledgement.path("outcomeSha256").asText()).isEqualTo(sha);
            assertThat(acknowledgement.path("resultVersion").asLong()).isEqualTo(1);
            if (management) {
                org.mockito.Mockito
                        .verify(managementAuthority)
                        .requireCurrent(org.mockito.ArgumentMatchers.eq(peer), org.mockito.ArgumentMatchers.any());
                org.mockito.Mockito
                        .verify(managementOutcomes)
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq(peer),
                                org.mockito.ArgumentMatchers.any());
            } else {
                org.mockito.Mockito
                        .verify(runAuthority)
                        .requireCurrent(org.mockito.ArgumentMatchers.eq(peer), org.mockito.ArgumentMatchers.any());
                org.mockito.Mockito
                        .verify(runOutcomes)
                        .append(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq(peer),
                                org.mockito.ArgumentMatchers.any());
            }
            verifyNoInteractions(runDispatch, managementDispatch, assignments);
        }
    }

    private static RuntimePeer outcomePeer(boolean management) {
        return new RuntimePeer(management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN,
                new RuntimeProxyCertificateClaims("cluster", "proof", "gateway", "pod", UUID.randomUUID()));
    }

    private static byte[] outcomeBody(boolean management, UUID intent, UUID correlation) throws Exception {
        Instant expiry = Instant.parse("2030-01-01T00:00:00Z");
        com.otilm.ai.runtime.protocol.DispatchEnvelope envelope = management
                ? new ManagementDispatchEnvelope(1, intent, "a".repeat(64),
                        new ManagementBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1,
                                ManagementAction.CONNECTION_CHECK, expiry))
                : new RunDispatchEnvelope(1, intent, "a".repeat(64), new RunBinding(UUID.randomUUID(),
                        UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1, expiry));
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var document = json
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", management ? "management-outcome" : "run-outcome")
                .put("intentId", intent.toString())
                .put("gatewayCorrelation", correlation.toString())
                .put("payloadSha256", envelope.payloadSha256())
                .put("transportCode", "UNKNOWN")
                .putNull("responseBase64")
                .putNull("responseSha256")
                .put("responseByteCount", 0);
        document.set("binding", json.readTree(new ProtocolCodec().writeDispatch(envelope)).get("binding"));
        document.putObject("usage").put("kind", "unknown");
        return json.writeValueAsBytes(document);
    }
}
