package com.otilm.core.config.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.secret.SecretRequestDto;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TraceBodyAdviceTest {

    private static final String PASSWORD = "basic-auth-password";
    private static final String SECRET_REQUEST = """
            {"name":"probe","secret":{"type":"basicAuth","username":"alice","password":"%s"}}
            """.formatted(PASSWORD);

    private final Logger adviceLogger = (Logger) LoggerFactory.getLogger(TraceBodyAdvice.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Level previousLevel;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        previousLevel = adviceLogger.getLevel();
        adviceLogger.setLevel(Level.TRACE);
        logged.start();
        adviceLogger.addAppender(logged);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ProbeController())
                .setControllerAdvice(new TraceBodyAdvice())
                .build();
    }

    @AfterEach
    void tearDown() {
        adviceLogger.detachAppender(logged);
        adviceLogger.setLevel(previousLevel);
    }

    @Test
    void aJsonRequestBody_isLoggedWithItsSecretRedacted() throws Exception {
        // when
        postSecret("/probe/secret");

        // then
        assertThat(line("REQUEST BODY"))
                .contains("\"username\":\"alice\"")
                .contains("\"password\":\"***\"")
                .doesNotContain(PASSWORD);
    }

    @Test
    void aJsonResponseBody_isLoggedWithItsSecretRedacted() throws Exception {
        // when
        postSecret("/probe/secret");

        // then
        assertThat(line("RESPONSE BODY")).contains("\"password\":\"***\"").doesNotContain(PASSWORD);
    }

    @Test
    void theBodyOfASensitiveParameter_isRedactedWhole() throws Exception {
        // when
        postSecret("/probe/sensitive");

        // then
        assertThat(line("REQUEST BODY")).isEqualTo("REQUEST BODY: ***");
    }

    @Test
    void aBinaryResponse_isLoggedAsItsTypeAndSize() throws Exception {
        // when
        mockMvc.perform(get("/probe/binary")).andExpect(status().isOk());

        // then
        assertThat(line("RESPONSE BODY")).isEqualTo("RESPONSE BODY: ByteArrayResource of 42 bytes");
    }

    @Test
    void aJsonStringResponse_isLoggedAsItsSizeNotItsText() throws Exception {
        // when
        mockMvc.perform(get("/probe/json-text")).andExpect(status().isOk());

        // then
        assertThat(line("RESPONSE BODY")).isEqualTo("RESPONSE BODY: String of 34 characters");
    }

    @Test
    void aBodyThatCannotBeWritten_doesNotFailTheRequest() throws Exception {
        // when
        mockMvc
                .perform(post("/probe/exploding").contentType(MediaType.APPLICATION_JSON).content("{\"value\":\"x\"}"))
                .andExpect(status().isOk());

        // then
        assertThat(line("REQUEST BODY")).isEqualTo("REQUEST BODY: [unserializable Exploding]");
    }

    @Test
    void nothingIsLoggedBelowTrace() throws Exception {
        // given
        adviceLogger.setLevel(Level.DEBUG);

        // when
        postSecret("/probe/secret");

        // then - nothing logged, and neither overload would have let Spring call this advice at all
        assertThat(logged.list).isEmpty();
        TraceBodyAdvice advice = new TraceBodyAdvice();
        assertThat(
                advice.supports(mock(MethodParameter.class), Object.class, MappingJackson2HttpMessageConverter.class))
                .isFalse();
        assertThat(advice.supports(mock(MethodParameter.class), MappingJackson2HttpMessageConverter.class)).isFalse();
    }

    @Test
    void aPlainTextRequestBody_isLoggedAsItsSize() throws Exception {
        // when
        mockMvc
                .perform(post("/probe/text").contentType(MediaType.TEXT_PLAIN).content("plain-text-body"))
                .andExpect(status().isOk());

        // then
        assertThat(line("REQUEST BODY")).isEqualTo("REQUEST BODY: String of 15 characters");
    }

    @Test
    void aByteArrayResponse_isLoggedAsItsSize() throws Exception {
        // when
        mockMvc.perform(get("/probe/bytes")).andExpect(status().isOk());

        // then
        assertThat(line("RESPONSE BODY")).isEqualTo("RESPONSE BODY: byte[] of 7 bytes");
    }

    @Test
    void aStreamedResponse_isLoggedByItsTypeAndStillSentWhole() throws Exception {
        // when
        MvcResult result = mockMvc.perform(get("/probe/stream")).andExpect(status().isOk()).andReturn();

        // then
        assertThat(line("RESPONSE BODY")).isEqualTo("RESPONSE BODY: InputStreamResource");
        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).isEqualTo("streamed-body");
    }

    @Test
    void summary_ofNoBody_isNone() {
        assertThat(TraceBodyAdvice.summary(null)).isEqualTo("none");
    }

    @Test
    void aJsonTypedByteArrayResponse_isSummarizedNotSerialized() {
        // Core registers no ByteArrayHttpMessageConverter, so nothing stops a byte[] body carrying a JSON media
        // type from reaching the Jackson converter branch; if it did, LogRedaction.json would log its content.
        new TraceBodyAdvice()
                .beforeBodyWrite(new byte[5], mock(MethodParameter.class), MediaType.APPLICATION_JSON,
                        MappingJackson2HttpMessageConverter.class, mock(ServerHttpRequest.class),
                        mock(ServerHttpResponse.class));

        assertThat(line("RESPONSE BODY")).isEqualTo("RESPONSE BODY: byte[] of 5 bytes");
    }

    private void postSecret(String path) throws Exception {
        mockMvc
                .perform(post(path).contentType(MediaType.APPLICATION_JSON).content(SECRET_REQUEST))
                .andExpect(status().isOk());
    }

    private String line(String prefix) {
        return logged.list
                .stream()
                .map(ILoggingEvent::getFormattedMessage)
                .filter(message -> message.startsWith(prefix))
                .findFirst()
                .orElseThrow();
    }

    @RestController
    static final class ProbeController {

        @PostMapping("/probe/secret")
        SecretRequestDto echo(@RequestBody SecretRequestDto request) {
            return request;
        }

        @PostMapping("/probe/sensitive")
        void sensitive(@Sensitive @RequestBody SecretRequestDto request) {
            // only the logged body is observed
        }

        @GetMapping("/probe/binary")
        ResponseEntity<Resource> binary() {
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(new ByteArrayResource(new byte[42]));
        }

        @GetMapping(path = "/probe/json-text", produces = MediaType.APPLICATION_JSON_VALUE)
        String jsonText() {
            return "{\"password\":\"" + PASSWORD + "\"}";
        }

        @PostMapping("/probe/exploding")
        void exploding(@RequestBody Exploding body) {
            // only the logged body is observed
        }

        @PostMapping("/probe/text")
        void text(@RequestBody String body) {
            // only the logged body is observed
        }

        @GetMapping("/probe/bytes")
        ResponseEntity<byte[]> bytes() {
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(new byte[7]);
        }

        @GetMapping("/probe/stream")
        ResponseEntity<Resource> stream() {
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(new InputStreamResource(
                            new ByteArrayInputStream("streamed-body".getBytes(StandardCharsets.UTF_8))));
        }
    }

    static final class Exploding {

        private String value;

        public void setValue(String value) {
            this.value = value;
        }

        public String getValue() {
            throw new IllegalStateException("not writable: " + value);
        }
    }
}
