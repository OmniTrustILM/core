package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.runtime.protocol.DispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;

/** Bounded syntax and exact-byte mapping only; no identity, permission, consumption or result-validity grant. */
public final class AiRuntimeGatewayWire {
    private static final String GATEWAY_CORRELATION = "gatewayCorrelation";
    private static final String PROTOCOL_VERSION = "protocolVersion";
    private static final String BINDING = "binding";
    private static final String INTENT_ID = "intentId";
    private static final String PAYLOAD_SHA256 = "payloadSha256";
    private static final String RESPONSE_SHA256 = "responseSha256";
    private static final String RESPONSE_BASE64 = "responseBase64";
    private static final int REDEEM_LIMIT = 8192;
    static final int DOCUMENT_LIMIT = 1_500_000;
    private static final int RESPONSE_LIMIT = 1_048_576;
    private static final Set<String> REDEEM_FIELDS = Set.of(PROTOCOL_VERSION, GATEWAY_CORRELATION, "envelope");
    static final Set<String> OUTCOME_FIELDS = Set
            .of(PROTOCOL_VERSION, "kind", INTENT_ID, GATEWAY_CORRELATION, BINDING, PAYLOAD_SHA256, "transportCode",
                    RESPONSE_BASE64, RESPONSE_SHA256, "responseByteCount", "usage");
    private static final ObjectMapper JSON = ObjectMapperFactory.aiGatewayWire();
    private static final ProtocolCodec PROTOCOL = new ProtocolCodec();

    public RedeemRequest readRedeem(byte[] input) {
        var document = parseRedeem(input);
        if (!(document.envelope() instanceof RunDispatchEnvelope run)) {
            throw invalid();
        }
        return new RedeemRequest(document.correlation(), run);
    }

    public OutcomeRequest readOutcome(byte[] input) {
        var document = parseOutcome(input, Encoding.RUN);
        if (!(document.envelope() instanceof RunDispatchEnvelope run)) {
            throw invalid();
        }
        var response = document.response();
        return new OutcomeRequest(1, document.kind(), run.intentId(), document.correlation(), run.binding(),
                run.payloadSha256(), response.transport(), response.base64(), response.sha256(), response.count(),
                Usage.UNKNOWN, document.sha256(), document.bytes(), response.bytes());
    }

    public byte[] consumedReply(ResolvedDispatch dispatch, RunBinding validatedBinding) {
        try {
            if (!dispatch.expiresAt().equals(validatedBinding.expiresAt())) {
                throw invalid();
            }
            var envelope = new RunDispatchEnvelope(1, dispatch.intentId(), dispatch.payload().sha256(),
                    validatedBinding);
            return writeConsumed(dispatch, envelope, Encoding.RUN);
        } catch (RuntimeException failure) {
            throw invalid();
        }
    }

    public byte[] acknowledgement(UUID intent, UUID correlation, String serverSha, long positiveVersion) {
        return writeAcknowledgement(intent, correlation, serverSha, positiveVersion, Encoding.RUN);
    }

    static ParsedRedeem parseRedeem(byte[] input) {
        try {
            var root = parse(input, REDEEM_LIMIT).root();
            closed(root, REDEEM_FIELDS);
            version(root);
            return new ParsedRedeem(uuid(root.get(GATEWAY_CORRELATION)),
                    PROTOCOL.readDispatch(JSON.writeValueAsBytes(root.get("envelope"))));
        } catch (IOException | RuntimeException failure) {
            throw invalid();
        }
    }

    static ParsedOutcome parseOutcome(byte[] input, Encoding encoding) {
        try {
            var document = parse(input, DOCUMENT_LIMIT);
            var root = document.root();
            closed(root, OUTCOME_FIELDS);
            version(root);
            String kind = text(root.get("kind"));
            if (!encoding.outcome.equals(kind)) {
                throw invalid();
            }
            var envelope = JSON
                    .createObjectNode()
                    .put("kind", encoding.dispatch)
                    .put(PROTOCOL_VERSION, 1)
                    .put(INTENT_ID, uuid(root.get(INTENT_ID)).toString())
                    .put(PAYLOAD_SHA256, digest(root.get(PAYLOAD_SHA256)));
            envelope.set(BINDING, root.get(BINDING));
            return new ParsedOutcome(kind, uuid(root.get(GATEWAY_CORRELATION)),
                    PROTOCOL.readDispatch(JSON.writeValueAsBytes(envelope)), readResponse(root),
                    sha256(document.bytes()), document.bytes());
        } catch (IOException | RuntimeException failure) {
            throw invalid();
        }
    }

    static byte[] writeConsumed(ResolvedDispatch dispatch, DispatchEnvelope envelope, Encoding encoding) {
        try {
            byte[] payload = dispatch.payload().bytes();
            String payloadSha = sha256(payload);
            var binding = JSON.readTree(PROTOCOL.writeDispatch(envelope)).get(BINDING);
            var root = JSON
                    .createObjectNode()
                    .put(PROTOCOL_VERSION, 1)
                    .put("kind", encoding.consumed)
                    .put(INTENT_ID, dispatch.intentId().toString())
                    .put(GATEWAY_CORRELATION, dispatch.gatewayCorrelation().toString());
            root.set(BINDING, binding);
            dispatchFields(root, dispatch, payload, payloadSha);
            return write(root, DOCUMENT_LIMIT);
        } catch (IOException | RuntimeException failure) {
            throw invalid();
        }
    }

    static byte[] writeAcknowledgement(UUID intent, UUID correlation, String sha, long positiveVersion,
            Encoding encoding) {
        try {
            var root = JSON.createObjectNode().put(PROTOCOL_VERSION, 1).put("kind", encoding.acknowledgement);
            acknowledgementFields(root, intent, correlation, sha, positiveVersion);
            return write(root, 4096);
        } catch (IOException | RuntimeException failure) {
            throw invalid();
        }
    }

    static void acknowledgementFields(com.fasterxml.jackson.databind.node.ObjectNode root, UUID intent,
            UUID correlation, String serverSha, long positiveVersion) {
        if (intent == null || correlation == null || serverSha == null || !serverSha.matches("[0-9a-f]{64}")
                || positiveVersion < 1) {
            throw invalid();
        }
        root
                .put(INTENT_ID, intent.toString())
                .put(GATEWAY_CORRELATION, correlation.toString())
                .put("outcomeSha256", serverSha)
                .put("resultVersion", positiveVersion);
    }

    static void dispatchFields(com.fasterxml.jackson.databind.node.ObjectNode root, ResolvedDispatch dispatch,
            byte[] payload, String payloadSha) {
        root.put(PAYLOAD_SHA256, payloadSha).put("payloadBase64", Base64.getEncoder().encodeToString(payload));
        var connection = dispatch.connection();
        root
                .putObject("connection")
                .put("id", connection.id().toString())
                .put("configuration", connection.configuration())
                .put("destination", connection.destination())
                .put("authentication", connection.authentication())
                .put("modelIdentifier", connection.modelIdentifier());
        root
                .put("outputTokens", dispatch.outputTokens())
                .put("origin", dispatch.origin().toString())
                .put("credentialReference", dispatch.credentialReference())
                .put("expiresAt", dispatch.expiresAt().toString());
    }

    static ResponseData readResponse(JsonNode root) {
        var usage = root.get("usage");
        closed(usage, Set.of("kind"));
        if (!"unknown".equals(text(usage.get("kind")))) {
            throw invalid();
        }
        TransportCode transport = TransportCode.valueOf(text(root.get("transportCode")));
        int count = (int) number(root.get("responseByteCount"), RESPONSE_LIMIT);
        String encoded = null;
        String responseSha = null;
        byte[] response = null;
        if (transport == TransportCode.UNKNOWN) {
            if (!root.get(RESPONSE_BASE64).isNull() || !root.get(RESPONSE_SHA256).isNull() || count != 0) {
                throw invalid();
            }
        } else {
            encoded = text(root.get(RESPONSE_BASE64));
            response = Base64.getDecoder().decode(encoded);
            responseSha = digest(root.get(RESPONSE_SHA256));
            if (response.length < 1 || response.length > RESPONSE_LIMIT || count != response.length
                    || !Base64.getEncoder().encodeToString(response).equals(encoded)
                    || !sha256(response).equals(responseSha)) {
                throw invalid();
            }
        }
        return new ResponseData(transport, encoded, responseSha, count, response);
    }

    static Document parse(byte[] input, int maximum) throws IOException {
        if (input == null || input.length < 1 || input.length > maximum) {
            throw invalid();
        }
        byte[] owned = input.clone();
        String text = StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(owned))
                .toString();
        if (text.startsWith("\uFEFF")) {
            throw invalid();
        }
        JsonNode root = JSON.readTree(text);
        if (root == null || !root.isObject()) {
            throw invalid();
        }
        unicode(root);
        return new Document(owned, root);
    }

    private static void unicode(JsonNode node) {
        if (node.isTextual()) {
            scalarText(node.textValue());
        } else if (node.isObject()) {
            node.fields().forEachRemaining(field -> {
                scalarText(field.getKey());
                unicode(field.getValue());
            });
        } else if (node.isArray()) {
            node.forEach(AiRuntimeGatewayWire::unicode);
        }
    }

    private static void scalarText(String text) {
        int index = 0;
        while (index < text.length()) {
            char current = text.charAt(index++);
            if (Character.isHighSurrogate(current)) {
                if (index == text.length() || !Character.isLowSurrogate(text.charAt(index++))) {
                    throw invalid();
                }
            } else if (Character.isLowSurrogate(current)) {
                throw invalid();
            }
        }
    }

    static void closed(JsonNode node, Set<String> names) {
        if (node == null || !node.isObject() || node.size() != names.size()
                || names.stream().anyMatch(name -> !node.has(name))) {
            throw invalid();
        }
    }

    static void version(JsonNode root) {
        if (number(root.get(PROTOCOL_VERSION), Integer.MAX_VALUE) != 1) {
            throw invalid();
        }
    }

    static String text(JsonNode node) {
        if (node == null || !node.isTextual()) {
            throw invalid();
        }
        return node.textValue();
    }

    static UUID uuid(JsonNode node) {
        String value = text(node);
        if (!value.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            throw invalid();
        }
        return UUID.fromString(value);
    }

    static String digest(JsonNode node) {
        String value = text(node);
        if (!value.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
        return value;
    }

    static long number(JsonNode node, long maximum) {
        if (node == null || !node.isIntegralNumber() || !node.canConvertToLong() || node.longValue() < 0
                || node.longValue() > maximum) {
            throw invalid();
        }
        return node.longValue();
    }

    static byte[] write(JsonNode value, int maximum) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(value);
        if (bytes.length > maximum) {
            throw invalid();
        }
        return bytes;
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException failure) {
            throw invalid();
        }
    }

    static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid gateway wire message");
    }

    public enum TransportCode {
        HTTP_200,
        UNKNOWN
    }

    public enum Usage {
        UNKNOWN
    }

    public record RedeemRequest(UUID correlation, RunDispatchEnvelope envelope) {
        public RedeemRequest {
            if (correlation == null || envelope == null) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "RedeemRequest[redacted]";
        }
    }

    public record OutcomeRequest(int protocolVersion, String kind, UUID intentId, UUID gatewayCorrelation,
            RunBinding binding, String payloadSha256, TransportCode transportCode, String responseBase64,
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
            return "OutcomeRequest[redacted]";
        }
    }

    // Fixed Core-local JSON encodings only. Public typed entry points still require their exact envelope type.
    enum Encoding {
        RUN("run", "run-outcome", "run-consumed", "run-outcome-recorded"),
        MANAGEMENT("management", "management-outcome", "management-consumed", "management-outcome-recorded");

        private final String dispatch;
        private final String outcome;
        private final String consumed;
        private final String acknowledgement;

        Encoding(String dispatch, String outcome, String consumed, String acknowledgement) {
            this.dispatch = dispatch;
            this.outcome = outcome;
            this.consumed = consumed;
            this.acknowledgement = acknowledgement;
        }
    }

    record ParsedOutcome(String kind, UUID correlation, DispatchEnvelope envelope, ResponseData response, String sha256,
            byte[] bytes) {
        @Override
        public String toString() {
            return "GatewayOutcomeDocument[redacted]";
        }
    }

    record ParsedRedeem(UUID correlation, com.otilm.ai.runtime.protocol.DispatchEnvelope envelope) {
        @Override
        public String toString() {
            return "GatewayRedeemDocument[redacted]";
        }
    }

    record ResponseData(TransportCode transport, String base64, String sha256, int count, byte[] bytes) {
        @Override
        public String toString() {
            return "GatewayResponseData[redacted]";
        }
    }

    record Document(byte[] bytes, JsonNode root) {
        @Override
        public String toString() {
            return "GatewayDocument[redacted]";
        }
    }
}
