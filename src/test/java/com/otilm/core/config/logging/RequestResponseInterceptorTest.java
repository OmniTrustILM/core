package com.otilm.core.config.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.util.ApplicationMessageConverters;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RequestResponseInterceptorTest {

    private final Logger interceptorLogger = (Logger) LoggerFactory.getLogger(RequestResponseInterceptor.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Level previousLevel;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        previousLevel = interceptorLogger.getLevel();
        interceptorLogger.setLevel(Level.TRACE);
        logged.start();
        interceptorLogger.addAppender(logged);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ProbeController())
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .addInterceptors(new RequestResponseInterceptor())
                .build();
    }

    @AfterEach
    void tearDown() {
        interceptorLogger.detachAppender(logged);
        interceptorLogger.setLevel(previousLevel);
        MDC.clear();
    }

    @ParameterizedTest(name = "{0}: {1}")
    @CsvSource(delimiter = '|', nullValues = "null",
            value = {
                    "Authorization       | Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig | Bearer ***",
                    "authorization       | Basic dXNlcjpwYXNz                  | Basic ***",
                    "Authorization       | opaque-credential                   | ***",
                    "Proxy-Authorization | Negotiate YIIB                      | Negotiate ***",
                    "Cookie              | SESSION=abc                         | ***",
                    "set-cookie          | SESSION=abc; HttpOnly               | ***",
                    "X-API-Key           | provisioning-key                    | ***",
                    "Accept              | application/json                    | application/json",
                    "Accept              | null                                | null"})
    void maskedHeaderValue_keepsOnlyWhatIsNotACredential(String name, String value, String expected) {
        assertThat(RequestResponseInterceptor.maskedHeaderValue(name, value)).isEqualTo(expected);
    }

    @Test
    void requestLine_masksCredentialsAndCarriesNoBody() throws Exception {
        // when
        mockMvc
                .perform(post("/probe/ok")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer header.claims.signature")
                        .header(HttpHeaders.COOKIE, "SESSION=session-identifier")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"request-body-secret\"}"))
                .andExpect(status().isOk());

        // then
        assertThat(line("REQUEST DATA"))
                .contains("Authorization : Bearer ***")
                .contains("Cookie : ***")
                .doesNotContain("header.claims.signature")
                .doesNotContain("session-identifier")
                .doesNotContain("request-body-secret");
    }

    @Test
    void responseLine_isLoggedForAHandlerThatThrew() throws Exception {
        // when
        mockMvc.perform(get("/probe/missing")).andExpect(status().isNotFound());

        // then
        assertThat(line("RESPONSE DATA")).contains("RESPONSE STATUS=404");
    }

    @Test
    void responseLine_masksEverySetCookie() throws Exception {
        // when
        mockMvc.perform(get("/probe/cookies")).andExpect(status().isOk());

        // then
        assertThat(line("RESPONSE DATA"))
                .contains("Set-Cookie : [***, ***]")
                .doesNotContain("first-session")
                .doesNotContain("second-session");
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

        @PostMapping("/probe/ok")
        void ok() {
            // only the logged lines are observed
        }

        @GetMapping("/probe/missing")
        void missing() throws NotFoundException {
            throw new NotFoundException("probe", "missing");
        }

        @GetMapping("/probe/cookies")
        void cookies(HttpServletResponse response) {
            response.addHeader(HttpHeaders.SET_COOKIE, "SESSION=first-session");
            response.addHeader(HttpHeaders.SET_COOKIE, "REMEMBER=second-session");
        }
    }
}
