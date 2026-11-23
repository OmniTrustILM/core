package com.otilm.core.model.ai;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

class AiModelRunResultTest {
    private static final String BODY = """
            {"model":"local-model","choices":[{"index":0,"finish_reason":"stop",
            "message":{"role":"assistant","content":"Certificate observations"}}],
            "usage":{"prompt_tokens":8,"completion_tokens":3,"total_tokens":11}}
            """;

    @Test
    void validatesExactModelTextAndIndependentlyCheckedUsage() {
        var result = validate(BODY);
        assertThat(result.code()).isEqualTo(AiModelRunResult.Code.TEXT);
        assertThat(result.text()).isEqualTo("Certificate observations");
        assertThat(result.finish()).isEqualTo(AiModelRunResult.Finish.STOP);
        assertThat(result.usage()).contains(new AiModelRunResult.Usage(8, 3, 11));
        assertThat(result.toString()).isEqualTo("ModelResult[code=TEXT]");
    }

    @Test
    void missingUsageRemainsUnknownAndLengthIsExplicit() {
        var result = validate(BODY
                .replace(",\n\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":3,\"total_tokens\":11}", "")
                .replace("\"stop\"", "\"length\""));
        assertThat(result.code()).isEqualTo(AiModelRunResult.Code.TEXT);
        assertThat(result.finish()).isEqualTo(AiModelRunResult.Finish.LENGTH);
        assertThat(result.usage()).isEmpty();
    }

    @Test
    void ignoresProviderExtensionMetadataWithoutTreatingItAsAuthority() {
        var body = BODY.replace("{\"model\"", "{\"provider_extension\":{\"actor\":\"foreign\"},\"model\"");
        assertThat(validate(body).text()).isEqualTo("Certificate observations");
    }

    @ParameterizedTest
    @MethodSource("invalidBodies")
    void invalidOrUnsupportedResultsHaveNoProtectedTextOrUsage(String body) {
        var result = validate(body);
        assertThat(result.code()).isEqualTo(AiModelRunResult.Code.INVALID);
        assertThat(result.text()).isNull();
        assertThat(result.finish()).isNull();
        assertThat(result.usage()).isEmpty();
        assertThat(result.toString()).isEqualTo("ModelResult[code=INVALID]");
    }

    static Stream<String> invalidBodies() {
        return Stream
                .of("", "null", "[]", "{}", "{", "\uFEFF" + BODY, BODY + "{}",
                        BODY.replace("\"local-model\"", "\"foreign-model\""),
                        BODY.replace("\"model\":\"local-model\"", "\"model\":1"),
                        BODY.replace("\"choices\":[", "\"choices\":null,\"ignored\":["),
                        BODY.replace("\"choices\":[", "\"choices\":[],\"ignored\":["),
                        BODY.replace("\"choices\":[", "\"choices\":[1],\"ignored\":["),
                        BODY.replace("\"index\":0", "\"index\":1"), BODY.replace("\"index\":0", "\"index\":0.0"),
                        BODY.replace("\"stop\"", "\"tool_calls\""), BODY.replace("\"stop\"", "null"),
                        BODY.replace("\"assistant\"", "\"tool\""),
                        BODY.replace("\"content\":\"Certificate observations\"", "\"content\":null"),
                        BODY.replace("Certificate observations", ""),
                        BODY.replace("Certificate observations", "\\u0000"),
                        BODY.replace("Certificate observations", "\\ud800"),
                        BODY.replace("Certificate observations", "x".repeat(65537)),
                        BODY.replace("\"role\":\"assistant\"", "\"tool_calls\":[{}],\"role\":\"assistant\""),
                        BODY.replace("\"role\":\"assistant\"", "\"function_call\":{},\"role\":\"assistant\""),
                        BODY.replace("\"role\":\"assistant\"", "\"role\":\"assistant\",\"role\":\"assistant\""),
                        BODY.replace("\"prompt_tokens\":8", "\"prompt_tokens\":-1"),
                        BODY.replace("\"prompt_tokens\":8", "\"prompt_tokens\":8.0"),
                        BODY.replace("\"prompt_tokens\":8", "\"prompt_tokens\":\"8\""),
                        BODY.replace("\"prompt_tokens\":8", "\"prompt_tokens\":9223372036854775807"),
                        BODY.replace("\"completion_tokens\":3", "\"completion_tokens\":17"),
                        BODY.replace("\"total_tokens\":11", "\"total_tokens\":10"),
                        BODY.replace("\"total_tokens\":11", "\"extra\":11"),
                        BODY.replace("\"usage\":{", "\"usage\":null,\"ignored\":{"),
                        BODY
                                .replace("{\"model\"",
                                        "{\"extension\":" + "[".repeat(20) + "0" + "]".repeat(20) + ",\"model\""));
    }

    @Test
    void twoOtherwiseValidChoicesAreRejected() throws Exception {
        var root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(BODY);
        var choices = (com.fasterxml.jackson.databind.node.ArrayNode) root.get("choices");
        choices.add(choices.get(0).deepCopy());
        assertThat(validate(root.toString()).code()).isEqualTo(AiModelRunResult.Code.INVALID);
    }

    @ParameterizedTest
    @MethodSource("invalidContentEncodings")
    void rejectsBadUtf8InsideAnOtherwiseValidResponse(byte[] invalid) {
        String prefix = BODY.substring(0, BODY.indexOf("Certificate observations"));
        String suffix = BODY.substring(BODY.indexOf("Certificate observations") + "Certificate observations".length());
        var bytes = new java.io.ByteArrayOutputStream();
        bytes.writeBytes(prefix.getBytes(StandardCharsets.UTF_8));
        bytes.writeBytes(invalid);
        bytes.writeBytes(suffix.getBytes(StandardCharsets.UTF_8));
        assertThat(AiModelRunResult.validate(bytes.toByteArray(), "local-model", 16).code())
                .isEqualTo(AiModelRunResult.Code.INVALID);
    }

    static Stream<byte[]> invalidContentEncodings() {
        return Stream
                .of(new byte[]{(byte) 0xc3, 0x28}, new byte[]{(byte) 0xc0, (byte) 0xaf},
                        new byte[]{(byte) 0xed, (byte) 0xa0, (byte) 0x80});
    }

    @Test
    void rejectsInvalidUtf8ExcessBytesAndInvalidStoredLimits() {
        assertThat(AiModelRunResult.validate(new byte[]{(byte) 0xc3, 0x28}, "local-model", 16).code())
                .isEqualTo(AiModelRunResult.Code.INVALID);
        String atLimit = BODY + " ".repeat(1048576 - BODY.getBytes(StandardCharsets.UTF_8).length);
        assertThat(validate(atLimit).code()).isEqualTo(AiModelRunResult.Code.TEXT);
        assertThat(validate(atLimit + " ").code()).isEqualTo(AiModelRunResult.Code.INVALID);
        assertThat(AiModelRunResult.validate(null, "local-model", 16).code()).isEqualTo(AiModelRunResult.Code.INVALID);
        assertThat(AiModelRunResult.validate(BODY.getBytes(StandardCharsets.UTF_8), null, 16).code())
                .isEqualTo(AiModelRunResult.Code.INVALID);
        assertThat(AiModelRunResult.validate(BODY.getBytes(StandardCharsets.UTF_8), "local-model", 0).code())
                .isEqualTo(AiModelRunResult.Code.INVALID);
    }

    private static AiModelRunResult.Validation validate(String body) {
        return AiModelRunResult.validate(body.getBytes(StandardCharsets.UTF_8), "local-model", 16);
    }
}
