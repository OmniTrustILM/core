package com.otilm.core.model.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/** Constructs and validates text Chat Completions without streaming against a reserved output limit. */
public final class AiModelDispatchPayload {
    private static final String MODEL = "model";
    private static final String MESSAGES = "messages";
    private static final String CONTENT = "content";
    private static final String MAX_TOKENS = "max_tokens";
    private static final String STREAM = "stream";
    private static final ObjectMapper JSON = ObjectMapperFactory.aiModelPayload();
    private static final Set<String> ROLES = Set.of("system", "user", "assistant");

    private AiModelDispatchPayload() {
    }

    /** Produces fixed version-one bytes from Core-prepared text; construction grants no dispatch authority. */
    public static ExactPayload text(String modelIdentifier, int outputTokens, String instructions, String prompt,
            String context) {
        if (!AiModelDispatchState.validModelIdentifier(modelIdentifier) || outputTokens <= 0
                || !validText(instructions, false) || !validText(prompt, false) || !validText(context, true)) {
            throw invalidText();
        }
        var root = JSON.createObjectNode();
        root.put(MODEL, modelIdentifier);
        var messages = root.putArray(MESSAGES);
        messages.addObject().put("role", "system").put(CONTENT, instructions);
        messages.addObject().put("role", "user").put(CONTENT, prompt);
        messages.addObject().put("role", "user").put(CONTENT, context);
        root.put(MAX_TOKENS, outputTokens);
        root.put(STREAM, false);
        try {
            return new ExactPayload(JSON.writeValueAsBytes(root));
        } catch (IOException | IllegalArgumentException failure) {
            throw invalidText();
        }
    }

    static boolean validText(String value, boolean allowEmpty) {
        if (value == null || value.length() > 65536 || (!allowEmpty && value.isBlank())) {
            return false;
        }
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index++);
            if (current == 0 || Character.isLowSurrogate(current)) {
                return false;
            }
            if (Character.isHighSurrogate(current)
                    && (index == value.length() || !Character.isLowSurrogate(value.charAt(index++)))) {
                return false;
            }
        }
        return true;
    }

    private static IllegalArgumentException invalidText() {
        return new IllegalArgumentException("Invalid model text payload");
    }

    public static boolean hasOutputLimit(ExactPayload payload, int outputTokens) {
        return validatedModel(payload, outputTokens) != null;
    }

    public static boolean hasModelAndOutputLimit(ExactPayload payload, int outputTokens, String modelIdentifier) {
        return AiModelDispatchState.validModelIdentifier(modelIdentifier)
                && modelIdentifier.equals(validatedModel(payload, outputTokens));
    }

    private static String validatedModel(ExactPayload payload, int outputTokens) {
        if (payload == null || outputTokens <= 0) {
            return null;
        }
        try {
            String text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload.bytes()))
                    .toString();
            if (text.startsWith("\uFEFF")) {
                return null;
            }
            JsonNode root = JSON.readTree(text);
            if (root == null || !root.isObject() || root.size() != 4 || !root.has(MODEL) || !root.has(MESSAGES)
                    || !root.has(MAX_TOKENS) || !root.has(STREAM)) {
                return null;
            }
            JsonNode model = root.get(MODEL);
            JsonNode tokens = root.get(MAX_TOKENS);
            JsonNode stream = root.get(STREAM);
            JsonNode messages = root.get(MESSAGES);
            if (!model.isTextual() || !AiModelDispatchState.validModelIdentifier(model.textValue())
                    || !tokens.isIntegralNumber() || !tokens.canConvertToInt() || tokens.intValue() != outputTokens
                    || !stream.isBoolean() || stream.booleanValue() || !messages.isArray() || messages.isEmpty()
                    || messages.size() > 64) {
                return null;
            }
            for (JsonNode message : messages) {
                if (!message.isObject() || message.size() != 2 || !message.has("role") || !message.has(CONTENT)) {
                    return null;
                }
                JsonNode role = message.get("role");
                JsonNode content = message.get(CONTENT);
                if (!role.isTextual() || !ROLES.contains(role.textValue()) || !content.isTextual()
                        || content.textValue().length() > 65536) {
                    return null;
                }
            }
            return model.textValue();
        } catch (IOException invalid) {
            return null;
        }
    }
}
