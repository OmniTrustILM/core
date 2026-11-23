package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiModelRunOutcome.Receipt;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiRuntimeGatewayServiceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ProtocolCodec CODEC = new ProtocolCodec();
    private static final UUID INTENT = UUID.randomUUID();
    private static final UUID CORRELATION = UUID.randomUUID();
    private static final Instant EXPIRY = Instant.parse("2030-01-01T00:00:00Z");
    private static final RunBinding BINDING = new RunBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
            UUID.randomUUID(), 7, EXPIRY);
    private static final ResolvedDispatch DISPATCH = new ResolvedDispatch(INTENT,
            new ConnectionVersion(UUID.randomUUID(), 2, 3, 4, "lab"),
            AiModelDispatchPayload.text("lab", 32, "instructions", "protected prompt", "protected context"), 32,
            URI.create("https://provider.invalid:8443"), "provider-reference", EXPIRY, CORRELATION);
    private static final RunDispatchEnvelope ENVELOPE = new RunDispatchEnvelope(1, INTENT, DISPATCH.payload().sha256(),
            BINDING);
    private final AiRuntimeGatewayAuthority authority = mock(AiRuntimeGatewayAuthority.class);
    private final AiModelRunDispatchService dispatch = mock(AiModelRunDispatchService.class);
    private final AiModelRunOutcomeWriter outcomes = mock(AiModelRunOutcomeWriter.class);
    private final AtomicLong nanos = new AtomicLong();
    private final AiRuntimeGatewayServiceImpl service = new AiRuntimeGatewayServiceImpl(authority, dispatch, outcomes,
            nanos::get, new AiFeatureGate(true));
    private final RuntimePeer peer = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims(
            "cluster-one", "ai-gateway", "gateway", "gateway-one", UUID.randomUUID()));
    private MockedStatic<RuntimeProxyTransport> transport;

    @BeforeEach
    void setup() {
        transport = mockStatic(RuntimeProxyTransport.class);
        transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
        when(dispatch.consume(eq(ENVELOPE), eq(CORRELATION), eq(peer), any())).thenReturn(Optional.of(DISPATCH));
    }

    @AfterEach
    void close() {
        transport.close();
        Thread.interrupted();
    }

    @Test
    void requiresNativePeerBeforeTouchingBodyOrCollaborators() {
        transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.empty());
        assertError(service.redeem(hostileBody()), RuntimeErrorCode.UNAUTHENTICATED);
        assertError(service.outcome(hostileBody()), RuntimeErrorCode.UNAUTHENTICATED);
        verifyNoInteractions(authority, dispatch, outcomes);
    }

    @ParameterizedTest
    @EnumSource(value = RuntimePeerRole.class, names = {"GATEWAY_RUN"}, mode = EnumSource.Mode.EXCLUDE)
    void wrongNativeAudienceCannotReadOrDispatch(RuntimePeerRole role) {
        transport
                .when(RuntimeProxyTransport::currentWorkloadPeer)
                .thenReturn(Optional.of(new RuntimePeer(role, peer.subject())));
        assertError(service.redeem(hostileBody()), RuntimeErrorCode.DENIED);
        assertError(service.outcome(hostileBody()), RuntimeErrorCode.DENIED);
        verifyNoInteractions(authority, dispatch, outcomes);
    }

    @Test
    void expiredOrRevokedRegistrationCannotReadTheBody() {
        when(authority.requireCurrent(eq(peer), any()))
                .thenThrow(new AccessDeniedException("private authority detail"));
        assertError(service.redeem(hostileBody()), RuntimeErrorCode.DENIED);
        assertError(service.outcome(hostileBody()), RuntimeErrorCode.DENIED);
        verifyNoInteractions(dispatch, outcomes);
    }

    @Test
    void freshRegistrationThenAssignmentThenNativeBusinessConsumeProducesExactReply() throws Exception {
        var response = service.redeem(redeem());
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getBody()).containsExactly(new AiRuntimeGatewayWire().consumedReply(DISPATCH, BINDING));
        var order = inOrder(authority, outcomes, dispatch);
        order.verify(authority).requireCurrent(eq(peer), any());
        order.verify(outcomes).requireAssigned(eq(INTENT), eq(peer), any());
        order.verify(dispatch).consume(eq(ENVELOPE), eq(CORRELATION), eq(peer), any());
        verify(dispatch, never()).consume(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void foreignAssignmentStopsBeforeBusinessReads() throws Exception {
        doThrow(new AccessDeniedException("private assignment detail"))
                .when(outcomes)
                .requireAssigned(eq(INTENT), eq(peer), any());
        assertError(service.redeem(redeem()), RuntimeErrorCode.DENIED);
        verifyNoInteractions(dispatch);
    }

    @Test
    void rejectedFinalConsumptionCannotBecomeAReplyOrLegacyRetry() throws Exception {
        when(dispatch.consume(eq(ENVELOPE), eq(CORRELATION), eq(peer), any())).thenReturn(Optional.empty());
        assertError(service.redeem(redeem()), RuntimeErrorCode.DENIED);
        verify(dispatch, never()).consume(any(), any(), any(AiRuntimeOperationBudget.class));
    }

    @Test
    void committedConsumptionFollowedByElapsedBudgetDoesNotReturnPayload() throws Exception {
        when(dispatch.consume(eq(ENVELOPE), eq(CORRELATION), eq(peer), any())).thenAnswer(call -> {
            nanos.set(5_000_000_000L);
            return Optional.of(DISPATCH);
        });
        assertError(service.redeem(redeem()), RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @ParameterizedTest
    @ValueSource(strings = {"intent", "correlation", "payload", "expiry"})
    void committedConsumptionWithMismatchedResolvedDispatchIsUnknown(String field) throws Exception {
        var changed = new ResolvedDispatch(field.equals("intent") ? UUID.randomUUID() : INTENT, DISPATCH.connection(),
                field.equals("payload")
                        ? AiModelDispatchPayload.text("lab", 32, "different", "prompt", "context")
                        : DISPATCH.payload(),
                32, DISPATCH.origin(), DISPATCH.credentialReference(),
                field.equals("expiry") ? EXPIRY.plusSeconds(1) : EXPIRY,
                field.equals("correlation") ? UUID.randomUUID() : CORRELATION);
        when(dispatch.consume(eq(ENVELOPE), eq(CORRELATION), eq(peer), any())).thenReturn(Optional.of(changed));
        assertError(service.redeem(redeem()), RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @Test
    void http200EvidencePassesExactProtectedBytesToStorageAndReturnsOnlyItsReceipt() throws Exception {
        byte[] response = "{\"model\":\"lab\",\"synthetic\":\"SYNTHETIC_RESPONSE_CANARY\"}"
                .getBytes(StandardCharsets.UTF_8);
        var document = (com.fasterxml.jackson.databind.node.ObjectNode) JSON.readTree(outcomeBytes());
        document
                .put("transportCode", "HTTP_200")
                .put("responseBase64", java.util.Base64.getEncoder().encodeToString(response))
                .put("responseSha256",
                        java.util.HexFormat
                                .of()
                                .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(response)))
                .put("responseByteCount", response.length);
        byte[] bytes = JSON.writeValueAsBytes(document);
        var expected = new AiRuntimeGatewayWire().readOutcome(bytes);
        when(outcomes.append(any(), eq(peer), any())).thenAnswer(call -> {
            AiRuntimeGatewayWire.OutcomeRequest actual = call.getArgument(0);
            assertThat(actual.requestBytes()).containsExactly(bytes);
            assertThat(actual.responseBytes()).containsExactly(response);
            return Transition.value(Status.APPLIED, new Receipt(INTENT, CORRELATION, expected.outcomeSha256(), 23));
        });
        var reply = service.outcome(new ByteArrayInputStream(bytes));
        assertThat(reply.getStatusCode().value()).isEqualTo(200);
        assertThat(reply.getBody())
                .containsExactly(
                        new AiRuntimeGatewayWire().acknowledgement(INTENT, CORRELATION, expected.outcomeSha256(), 23));
        assertThat(new String(reply.getBody(), StandardCharsets.UTF_8))
                .doesNotContain("SYNTHETIC_RESPONSE_CANARY", document.get("responseBase64").textValue());
    }

    @Test
    void actualOutcomeReceiptAloneSuppliesTheAcknowledgement() throws Exception {
        byte[] bytes = outcomeBytes();
        var request = new AiRuntimeGatewayWire().readOutcome(bytes);
        when(outcomes.append(any(), eq(peer), any()))
                .thenReturn(Transition
                        .value(Status.APPLIED, new Receipt(INTENT, CORRELATION, request.outcomeSha256(), 19)));
        var response = service.outcome(new ByteArrayInputStream(bytes));
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody())
                .containsExactly(
                        new AiRuntimeGatewayWire().acknowledgement(INTENT, CORRELATION, request.outcomeSha256(), 19));
        verifyNoInteractions(dispatch);
    }

    @Test
    void exactReplayUsesTheSameStoredVersion() throws Exception {
        var request = new AiRuntimeGatewayWire().readOutcome(outcomeBytes());
        when(outcomes.append(any(), eq(peer), any()))
                .thenReturn(
                        Transition.value(Status.REPLAY, new Receipt(INTENT, CORRELATION, request.outcomeSha256(), 19)));
        assertThat(JSON
                .readTree(service.outcome(new ByteArrayInputStream(outcomeBytes())).getBody())
                .get("resultVersion")
                .longValue()).isEqualTo(19);
    }

    @ParameterizedTest
    @EnumSource(value = Status.class, names = {"DENIED", "CONFLICT"})
    void noReceiptCannotInventAnAcknowledgement(Status status) throws Exception {
        when(outcomes.append(any(), eq(peer), any())).thenReturn(Transition.empty(status));
        assertError(service.outcome(new ByteArrayInputStream(outcomeBytes())),
                status == Status.CONFLICT ? RuntimeErrorCode.CONFLICT : RuntimeErrorCode.DENIED);
    }

    @Test
    void outcomeExceptionOrWrongReceiptAfterWriterBeginsIsUnknown() throws Exception {
        when(outcomes.append(any(), eq(peer), any())).thenThrow(new IllegalStateException("private SQL detail"));
        assertError(service.outcome(new ByteArrayInputStream(outcomeBytes())), RuntimeErrorCode.UNKNOWN_OUTCOME);
        when(outcomes.append(any(), eq(peer), any()))
                .thenReturn(Transition
                        .value(Status.APPLIED, new Receipt(UUID.randomUUID(), CORRELATION, "a".repeat(64), 1)));
        assertError(service.outcome(new ByteArrayInputStream(outcomeBytes())), RuntimeErrorCode.UNKNOWN_OUTCOME);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void boundedMalformedBodiesNeverReachWriters(boolean outcome) {
        var response = outcome ? service.outcome(stream("{}")) : service.redeem(stream("{}"));
        assertError(response, RuntimeErrorCode.INVALID_REQUEST);
        verifyNoInteractions(dispatch, outcomes);
        var oversized = new ByteArrayInputStream(new byte[outcome ? 1_500_001 : 8193]);
        assertError(outcome ? service.outcome(oversized) : service.redeem(oversized), RuntimeErrorCode.LIMIT_EXCEEDED);
        verifyNoInteractions(dispatch, outcomes);
    }

    @Test
    void ioAndUnexpectedPreWriterFailuresAreContentFreeUnavailable() {
        InputStream broken = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("private stream detail");
            }
        };
        assertError(service.redeem(broken), RuntimeErrorCode.UNAVAILABLE);
        when(authority.requireCurrent(eq(peer), any())).thenThrow(new IllegalStateException("private key detail"));
        assertError(service.outcome(hostileBody()), RuntimeErrorCode.UNAVAILABLE);
    }

    @Test
    void interruptionIsPreservedAndCannotTouchAuthority() {
        Thread.currentThread().interrupt();
        assertError(service.redeem(hostileBody()), RuntimeErrorCode.INTERRUPTED);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
        verifyNoInteractions(authority, dispatch, outcomes);
    }

    private static InputStream redeem() throws Exception {
        var root = JSON.createObjectNode().put("protocolVersion", 1).put("gatewayCorrelation", CORRELATION.toString());
        root.set("envelope", JSON.readTree(CODEC.writeDispatch(ENVELOPE)));
        return new ByteArrayInputStream(JSON.writeValueAsBytes(root));
    }

    private static byte[] outcomeBytes() throws Exception {
        var root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CORRELATION.toString());
        root.set("binding", JSON.readTree(CODEC.writeDispatch(ENVELOPE)).get("binding"));
        root
                .put("payloadSha256", ENVELOPE.payloadSha256())
                .put("transportCode", "UNKNOWN")
                .putNull("responseBase64")
                .putNull("responseSha256")
                .put("responseByteCount", 0);
        root.putObject("usage").put("kind", "unknown");
        return JSON.writeValueAsBytes(root);
    }

    private static InputStream stream(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    private static InputStream hostileBody() {
        return new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("Body must not be read before native current identity");
            }
        };
    }

    private static void assertError(ResponseEntity<byte[]> response, RuntimeErrorCode code) {
        assertThat(response.getStatusCode().isError()).isTrue();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        var error = CODEC.readRuntimeError(response.getBody());
        assertThat(error.code()).isEqualTo(code);
        assertThat(new String(response.getBody(), StandardCharsets.UTF_8))
                .doesNotContain("private", "protected prompt", "protected context", "provider-reference");
    }
}
