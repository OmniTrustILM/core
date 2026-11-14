package com.otilm.core.model.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Bounded text-result interpretation; no dispatch, tool, reader or run-completion authority. */
public final class AiModelRunResult {
    private static final int MAX_BYTES = 1048576;
    private static final ObjectMapper JSON = ObjectMapperFactory.aiModelResult();
    private static final Validation INVALID = new Validation(Code.INVALID, null, null, Optional.empty());

    private AiModelRunResult() {
    }

    public static Validation validate(byte[] response, String modelIdentifier, int outputTokens) {
        if (response == null || response.length == 0 || response.length > MAX_BYTES
                || !AiModelDispatchState.validModelIdentifier(modelIdentifier) || outputTokens <= 0) {
            return INVALID;
        }
        try {
            String text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(response))
                    .toString();
            if (text.startsWith("\uFEFF")) {
                return INVALID;
            }
            JsonNode root = JSON.readTree(text);
            if (root == null || !root.isObject() || !root.path("model").isTextual()
                    || !modelIdentifier.equals(root.path("model").textValue())) {
                return INVALID;
            }
            return interpret(root, outputTokens);
        } catch (IOException | IllegalArgumentException | ArithmeticException failure) {
            return INVALID;
        }
    }

    private static Validation interpret(JsonNode root, int outputTokens) {
        JsonNode choices = root.path("choices");
        if (!choices.isArray() || choices.size() != 1) {
            return INVALID;
        }
        JsonNode choice = choices.get(0);
        JsonNode index = choice.path("index");
        JsonNode reason = choice.path("finish_reason");
        if (!choice.isObject() || !index.isIntegralNumber() || !index.canConvertToInt() || index.intValue() != 0
                || !reason.isTextual()) {
            return INVALID;
        }
        Finish finish = switch (reason.textValue()) {
            case "stop" -> Finish.STOP;
            case "length" -> Finish.LENGTH;
            default -> null;
        };
        JsonNode message = choice.path("message");
        JsonNode content = message.path("content");
        if (finish == null || !message.isObject() || !message.path("role").isTextual()
                || !"assistant".equals(message.path("role").textValue()) || !content.isTextual()
                || !AiModelDispatchPayload.validText(content.textValue(), false) || hasToolAction(message)) {
            return INVALID;
        }
        Optional<Usage> usage = root.has("usage")
                ? Optional.of(usage(root.get("usage"), outputTokens))
                : Optional.empty();
        return new Validation(Code.TEXT, content.textValue(), finish, usage);
    }

    private static boolean hasToolAction(JsonNode message) {
        JsonNode tools = message.get("tool_calls");
        JsonNode function = message.get("function_call");
        return (tools != null && !tools.isNull() && (!tools.isArray() || !tools.isEmpty()))
                || (function != null && !function.isNull());
    }

    private static Usage usage(JsonNode node, int outputTokens) {
        if (!node.isObject()) {
            throw invalid();
        }
        long prompt = count(node.path("prompt_tokens"));
        long completion = count(node.path("completion_tokens"));
        long total = count(node.path("total_tokens"));
        if (completion > outputTokens || Math.addExact(prompt, completion) != total) {
            throw invalid();
        }
        return new Usage(prompt, completion, total);
    }

    private static long count(JsonNode node) {
        if (!node.isIntegralNumber() || !node.canConvertToLong() || node.longValue() < 0) {
            throw invalid();
        }
        return node.longValue();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid model result");
    }

    public enum Code {
        TEXT,
        INVALID
    }

    public enum Finish {
        STOP,
        LENGTH
    }

    public record Usage(long promptTokens, long completionTokens, long totalTokens) {
    }

    public record Validation(Code code, String text, Finish finish, Optional<Usage> usage) {
        @Override
        public String toString() {
            return "ModelResult[code=" + code + "]";
        }
    }
}
