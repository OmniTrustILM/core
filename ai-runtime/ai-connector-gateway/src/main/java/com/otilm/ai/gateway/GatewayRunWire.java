package com.otilm.ai.gateway;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.DispatchEnvelope;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Closed gateway wire syntax only; never a Core identity, consumption or result-validity grant. */
final class GatewayRunWire {
    static final int DOCUMENT_LIMIT = 1_500_000;
    static final int RESPONSE_LIMIT = 1_048_576;
    static final ObjectMapper JSON = new ObjectMapper(JsonFactory
            .builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .streamReadConstraints(StreamReadConstraints
                    .builder()
                    .maxNestingDepth(16)
                    .maxNameLength(128)
                    .maxNumberLength(20)
                    .maxStringLength(DOCUMENT_LIMIT)
                    .build())
            .build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final ObjectMapper RESPONSE_JSON = new ObjectMapper(JsonFactory
            .builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .streamReadConstraints(StreamReadConstraints
                    .builder()
                    .maxNestingDepth(256)
                    .maxNumberLength(1000)
                    .maxStringLength(RESPONSE_LIMIT)
                    .build())
            .build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final ProtocolCodec PROTOCOL = new ProtocolCodec();

    record Connection(UUID id, long configuration, long destination, long authentication, String modelIdentifier) {
        @Override
        public String toString() {
            return "Connection[redacted]";
        }
    }

    record Consumed(Connection connection, byte[] payload, int outputTokens, URI origin, String credentialReference,
            Instant expiresAt) {
        Consumed {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }

        @Override
        public String toString() {
            return "Consumed[redacted]";
        }
    }

    static Consumed consumed(byte[] bytes, DispatchEnvelope envelope, UUID correlation) {
        try {
            var root = parse(bytes, DOCUMENT_LIMIT);
            fields(root, "protocolVersion", "kind", "intentId", "gatewayCorrelation", "binding", "payloadSha256",
                    "payloadBase64", "connection", "outputTokens", "origin", "credentialReference", "expiresAt");
            common(root, kind(envelope) + "-consumed", envelope, correlation);
            String digest = text(root, "payloadSha256");
            if (!digest.equals(envelope.payloadSha256())) {
                throw invalid();
            }
            var rebuilt = JSON
                    .createObjectNode()
                    .put("kind", kind(envelope))
                    .put("protocolVersion", 1)
                    .put("intentId", envelope.intentId().toString())
                    .put("payloadSha256", digest);
            rebuilt.set("binding", root.get("binding"));
            if (!envelope.equals(PROTOCOL.readDispatch(encode(rebuilt, DOCUMENT_LIMIT)))) {
                throw invalid();
            }
            byte[] payload = decoded(text(root, "payloadBase64"));
            if (!PayloadFingerprint.sha256(payload).equals(digest)) {
                throw invalid();
            }
            Instant expiry = Instant.parse(text(root, "expiresAt"));
            if (!expiry.equals(expiresAt(envelope)) || !expiry.isAfter(Instant.now())) {
                throw invalid();
            }
            var connection = connection(root.get("connection"));
            if (envelope instanceof ManagementDispatchEnvelope management
                    && (!connection.id().equals(management.binding().configurationId())
                            || connection.configuration() != management.binding().configurationRevision())) {
                throw invalid();
            }
            return new Consumed(connection, payload, (int) positive(root, "outputTokens", Integer.MAX_VALUE),
                    origin(text(root, "origin")), reference(text(root, "credentialReference")), expiry);
        } catch (RuntimeException invalid) {
            throw invalid();
        }
    }

    static Connection connection(JsonNode node) {
        fields(node, "id", "configuration", "destination", "authentication", "modelIdentifier");
        String model = text(node, "modelIdentifier");
        if (model.isBlank() || model.indexOf(0) >= 0 || model.codePointCount(0, model.length()) > 255) {
            throw invalid();
        }
        return new Connection(uuid(node, "id"), positive(node, "configuration", Long.MAX_VALUE),
                positive(node, "destination", Long.MAX_VALUE), positive(node, "authentication", Long.MAX_VALUE), model);
    }

    static URI origin(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                    || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || (!uri.getRawPath().isEmpty() && !uri.getRawPath().equals("/")) || uri.getPort() == 0
                    || uri.getPort() > 65535) {
                throw invalid();
            }
            return uri;
        } catch (RuntimeException bad) {
            throw invalid();
        }
    }

    static String reference(String value) {
        if (!value.matches("[a-z][a-z0-9-]{0,63}")) {
            throw invalid();
        }
        return value;
    }

    static byte[] redeem(DispatchEnvelope envelope, UUID correlation) {
        try {
            var root = JSON
                    .createObjectNode()
                    .put("protocolVersion", 1)
                    .put("gatewayCorrelation", correlation.toString());
            root.set("envelope", JSON.readTree(PROTOCOL.writeDispatch(envelope)));
            return encode(root, 8192);
        } catch (IOException | RuntimeException bad) {
            throw invalid();
        }
    }

    static byte[] outcome(DispatchEnvelope envelope, UUID correlation, byte[] response) {
        try {
            if (response != null && (response.length == 0 || response.length > RESPONSE_LIMIT)) {
                throw invalid();
            }
            var root = JSON
                    .createObjectNode()
                    .put("protocolVersion", 1)
                    .put("kind", kind(envelope) + "-outcome")
                    .put("intentId", envelope.intentId().toString())
                    .put("gatewayCorrelation", correlation.toString());
            root.set("binding", JSON.readTree(PROTOCOL.writeDispatch(envelope)).get("binding"));
            root
                    .put("payloadSha256", envelope.payloadSha256())
                    .put("transportCode", response == null ? "UNKNOWN" : "HTTP_200");
            if (response == null) {
                root.putNull("responseBase64").putNull("responseSha256").put("responseByteCount", 0);
            } else {
                root
                        .put("responseBase64", Base64.getEncoder().encodeToString(response))
                        .put("responseSha256", PayloadFingerprint.sha256(response))
                        .put("responseByteCount", response.length);
            }
            root.putObject("usage").put("kind", "unknown");
            return encode(root, DOCUMENT_LIMIT);
        } catch (IOException | RuntimeException bad) {
            throw invalid();
        }
    }

    static long acknowledgement(byte[] bytes, DispatchEnvelope envelope, UUID correlation, byte[] outcome) {
        try {
            var root = parse(bytes, 4096);
            fields(root, "protocolVersion", "kind", "intentId", "gatewayCorrelation", "outcomeSha256", "resultVersion");
            common(root, kind(envelope) + "-outcome-recorded", envelope, correlation);
            if (outcome == null || outcome.length == 0 || outcome.length > DOCUMENT_LIMIT
                    || !java.util.HexFormat
                            .of()
                            .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(outcome))
                            .equals(text(root, "outcomeSha256"))) {
                throw invalid();
            }
            return positive(root, "resultVersion", Long.MAX_VALUE);
        } catch (java.security.NoSuchAlgorithmException | RuntimeException bad) {
            throw invalid();
        }
    }

    static byte[] safeResponse(byte[] bytes, String bearer) {
        JsonNode root = parse(bytes, RESPONSE_LIMIT, RESPONSE_JSON);
        if (new String(bytes, StandardCharsets.UTF_8).contains(bearer)) {
            throw invalid();
        }
        var nodes = new ArrayDeque<JsonNode>();
        nodes.add(root);
        while (!nodes.isEmpty()) {
            var node = nodes.removeFirst();
            if (node.isTextual() && node.textValue().contains(bearer)) {
                throw invalid();
            }
            node.fieldNames().forEachRemaining(name -> {
                if (name.contains(bearer)) {
                    throw invalid();
                }
            });
            node.elements().forEachRemaining(nodes::addLast);
        }
        return bytes.clone();
    }

    static JsonNode parse(byte[] bytes, int maximum) {
        return parse(bytes, maximum, JSON);
    }

    private static JsonNode parse(byte[] bytes, int maximum, ObjectMapper mapper) {
        try {
            if (bytes == null || bytes.length == 0 || bytes.length > maximum) {
                throw invalid();
            }
            String decoded = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
            if (decoded.startsWith("\ufeff")) {
                throw invalid();
            }
            JsonNode root = mapper.readTree(decoded);
            if (root == null || !root.isObject()) {
                throw invalid();
            }
            var nodes = new ArrayDeque<JsonNode>();
            nodes.add(root);
            while (!nodes.isEmpty()) {
                var node = nodes.removeFirst();
                if (node.isTextual()) {
                    scalar(node.textValue());
                }
                node.fieldNames().forEachRemaining(GatewayRunWire::scalar);
                node.elements().forEachRemaining(nodes::addLast);
            }
            return root;
        } catch (IOException | RuntimeException bad) {
            throw invalid();
        }
    }

    private static void scalar(String value) {
        for (int n = 0; n < value.length(); n++) {
            char c = value.charAt(n);
            if (Character.isHighSurrogate(c)) {
                if (++n >= value.length() || !Character.isLowSurrogate(value.charAt(n))) {
                    throw invalid();
                }
            } else if (Character.isLowSurrogate(c)) {
                throw invalid();
            }
        }
    }

    static void fields(JsonNode node, String... expected) {
        if (node == null || !node.isObject()) {
            throw invalid();
        }
        Set<String> actual = new HashSet<>();
        node.fieldNames().forEachRemaining(actual::add);
        if (!actual.equals(Set.of(expected))) {
            throw invalid();
        }
    }

    static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual()) {
            throw invalid();
        }
        return value.textValue();
    }

    static long positive(JsonNode node, String field, long maximum) {
        JsonNode value = node.get(field);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() < 1
                || value.longValue() > maximum) {
            throw invalid();
        }
        return value.longValue();
    }

    static UUID uuid(JsonNode node, String field) {
        String value = text(node, field);
        UUID id = UUID.fromString(value);
        if (!id.toString().equals(value)) {
            throw invalid();
        }
        return id;
    }

    private static void common(JsonNode root, String kind, DispatchEnvelope envelope, UUID correlation) {
        if (positive(root, "protocolVersion", 1) != 1 || !kind.equals(text(root, "kind"))
                || !envelope.intentId().equals(uuid(root, "intentId"))
                || !correlation.equals(uuid(root, "gatewayCorrelation"))) {
            throw invalid();
        }
    }

    private static String kind(DispatchEnvelope envelope) {
        return switch (envelope) {
            case RunDispatchEnvelope ignored -> "run";
            case ManagementDispatchEnvelope ignored -> "management";
        };
    }

    private static Instant expiresAt(DispatchEnvelope envelope) {
        return switch (envelope) {
            case RunDispatchEnvelope run -> run.binding().expiresAt();
            case ManagementDispatchEnvelope management -> management.binding().expiresAt();
        };
    }

    private static byte[] decoded(String value) {
        byte[] bytes = Base64.getDecoder().decode(value);
        if (bytes.length == 0 || bytes.length > RESPONSE_LIMIT
                || !Base64.getEncoder().encodeToString(bytes).equals(value)) {
            throw invalid();
        }
        return bytes;
    }

    private static byte[] encode(ObjectNode root, int maximum) {
        try {
            byte[] bytes = JSON.writeValueAsBytes(root);
            if (bytes.length > maximum) {
                throw invalid();
            }
            return bytes;
        } catch (IOException bad) {
            throw invalid();
        }
    }

    static GatewayFailure invalid() {
        return new GatewayFailure(GatewayFailure.Code.INVALID_REQUEST);
    }
}
