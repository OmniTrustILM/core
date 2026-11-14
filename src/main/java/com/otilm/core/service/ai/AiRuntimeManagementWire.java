package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.Encoding;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.TransportCode;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.Usage;
import java.util.UUID;

import static com.otilm.core.service.ai.AiRuntimeGatewayWire.invalid;
import static com.otilm.core.service.ai.AiRuntimeGatewayWire.parseOutcome;
import static com.otilm.core.service.ai.AiRuntimeGatewayWire.parseRedeem;
import static com.otilm.core.service.ai.AiRuntimeGatewayWire.writeAcknowledgement;
import static com.otilm.core.service.ai.AiRuntimeGatewayWire.writeConsumed;

/** Closed management syntax/mapping only. Neither construction nor a public binding supplies CONNECT authority. */
public final class AiRuntimeManagementWire {
    public RedeemRequest readRedeem(byte[] input) {
        var document = parseRedeem(input);
        if (!(document.envelope() instanceof ManagementDispatchEnvelope management)) {
            throw invalid();
        }
        return new RedeemRequest(document.correlation(), management);
    }

    public OutcomeRequest readOutcome(byte[] input) {
        var document = parseOutcome(input, Encoding.MANAGEMENT);
        if (!(document.envelope() instanceof ManagementDispatchEnvelope management)) {
            throw invalid();
        }
        var response = document.response();
        return new OutcomeRequest(1, document.kind(), management.intentId(), document.correlation(),
                management.binding(), management.payloadSha256(), response.transport(), response.base64(),
                response.sha256(), response.count(), Usage.UNKNOWN, document.sha256(), document.bytes(),
                response.bytes());
    }

    public byte[] consumedReply(ResolvedDispatch dispatch, ManagementBinding validatedBinding) {
        try {
            var connection = dispatch.connection();
            if (!connection.id().equals(validatedBinding.configurationId())
                    || connection.configuration() != validatedBinding.configurationRevision()
                    || !dispatch.expiresAt().equals(validatedBinding.expiresAt())) {
                throw invalid();
            }
            var envelope = new ManagementDispatchEnvelope(1, dispatch.intentId(), dispatch.payload().sha256(),
                    validatedBinding);
            return writeConsumed(dispatch, envelope, Encoding.MANAGEMENT);
        } catch (RuntimeException failure) {
            throw invalid();
        }
    }

    public byte[] acknowledgement(UUID intent, UUID correlation, String serverSha, long positiveVersion) {
        return writeAcknowledgement(intent, correlation, serverSha, positiveVersion, Encoding.MANAGEMENT);
    }

    public record RedeemRequest(UUID correlation, ManagementDispatchEnvelope envelope) {
        public RedeemRequest {
            if (correlation == null || envelope == null) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementRedeemRequest[redacted]";
        }
    }

    public record OutcomeRequest(int protocolVersion, String kind, UUID intentId, UUID gatewayCorrelation,
            ManagementBinding binding, String payloadSha256, TransportCode transportCode, String responseBase64,
            String responseSha256, int responseByteCount, Usage usage, String outcomeSha256, byte[] requestBytes,
            byte[] responseBytes) {
        public OutcomeRequest {
            if (requestBytes == null) {
                throw invalid();
            }
            requestBytes = requestBytes.clone();
            responseBytes = responseBytes == null ? null : responseBytes.clone();
        }

        @Override
        public byte[] requestBytes() {
            return requestBytes.clone();
        }

        @Override
        public byte[] responseBytes() {
            return responseBytes == null ? null : responseBytes.clone();
        }

        @Override
        public String toString() {
            return "ManagementOutcomeRequest[redacted]";
        }
    }
}
