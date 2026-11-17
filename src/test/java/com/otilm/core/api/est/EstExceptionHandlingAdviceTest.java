package com.otilm.core.api.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;

import static org.assertj.core.api.Assertions.assertThat;

class EstExceptionHandlingAdviceTest {

    private static final MediaType PLAIN_TEXT_UTF8 = MediaType.parseMediaType("text/plain; charset=UTF-8");
    private static final String SECRET_DETAIL = "jdbc:postgresql://db.internal:5432/core password=hunter2";

    private final EstExceptionHandlingAdvice advice = new EstExceptionHandlingAdvice();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger adviceLogger = (Logger) LoggerFactory.getLogger(EstExceptionHandlingAdvice.class);

    @BeforeEach
    void captureTheAdviceLog() {
        logged.start();
        adviceLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheAdviceLog() {
        adviceLogger.detachAppender(logged);
        logged.stop();
    }

    // ── EstRefusals ───────────────────────────────────────────────────────────

    @Nested
    class EstRefusals {

        @Test
        void answersWithTheStatusAndTextOfTheError_whenEstExceptionIsHandled() {
            // given
            EstException refusal = new EstException(EstError.NOT_FOUND);

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getHeaders().getContentType()).isEqualTo(PLAIN_TEXT_UTF8);
            assertThat(textOf(response)).isEqualTo(EstError.NOT_FOUND.text());
        }

        @Test
        void challengesWithTheRealmOfTheException_whenTheErrorChallenges() {
            // given
            EstException refusal = new EstException(EstError.UNAUTHORIZED, "devices");

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"devices\", charset=\"UTF-8\"");
        }

        @Test
        void challengesWithTheDefaultRealm_whenTheExceptionNamesNone() {
            // given
            EstException refusal = new EstException(EstError.UNAUTHORIZED);

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"est\", charset=\"UTF-8\"");
        }

        @Test
        void sendsNoChallenge_whenTheErrorDoesNotChallenge() {
            // given
            EstException refusal = new EstException(EstError.CERTIFICATE_REJECTED, "devices");

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(response.getHeaders().containsHeader(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
        }

        @Test
        void appendsDetail_whenRefusalCarriesOne() {
            // given
            EstException refusal = new EstException(EstError.POLICY_VIOLATION, "devices")
                    .withDetail("The subject must contain a common name.");

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(textOf(response))
                    .isEqualTo(EstError.POLICY_VIOLATION.text() + " The subject must contain a common name.");
        }

        @Test
        void writesFixedSentenceOnly_whenRefusalCarriesNoDetail() {
            // given
            EstException refusal = new EstException(EstError.POLICY_VIOLATION, "devices");

            // when
            ResponseEntity<byte[]> response = advice.handleEstException(refusal);

            // then
            assertThat(textOf(response)).isEqualTo(EstError.POLICY_VIOLATION.text());
        }

        @Test
        void doesNotLogTheDetail_whenRefusalCarriesOne() {
            // given
            EstException refusal = new EstException(EstError.POLICY_VIOLATION, "devices")
                    .withDetail("CN=secret-device");

            // when
            advice.handleEstException(refusal);

            // then
            assertThat(logged.list).singleElement().satisfies(event -> {
                assertThat(event.getFormattedMessage()).doesNotContain("secret-device");
                assertThat(event.getThrowableProxy()).isNull();
            });
        }

        @Test
        void logsWarnWithRealmAndErrorCategory_whenRefusalNamesARealm() {
            // given
            EstException refusal = new EstException(EstError.SERVICE_UNAVAILABLE, "devices");

            // when
            advice.handleEstException(refusal);

            // then
            assertThat(logged.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage()).contains("SERVICE_UNAVAILABLE").contains("devices");
                assertThat(event.getThrowableProxy()).isNull();
            });
        }

        @Test
        void logsDashInPlaceOfRealm_whenRefusalNamesNone() {
            // given
            EstException refusal = new EstException(EstError.PAYLOAD_TOO_LARGE);

            // when
            advice.handleEstException(refusal);

            // then
            assertThat(logged.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                        .isEqualTo("EST request refused as PAYLOAD_TOO_LARGE for realm -");
            });
        }
    }

    // ── UnreadableBody ────────────────────────────────────────────────────────

    @Nested
    class UnreadableBody {

        @Test
        void answersBadRequest_whenTheBodyCannotBeRead() {
            // given
            HttpMessageNotReadableException unreadable = new HttpMessageNotReadableException(SECRET_DETAIL,
                    new MockHttpInputMessage(new byte[0]));

            // when
            ResponseEntity<byte[]> response = advice.handleUnreadableBody(unreadable);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getHeaders().getContentType()).isEqualTo(PLAIN_TEXT_UTF8);
            assertThat(textOf(response)).isEqualTo(EstError.BAD_REQUEST.text());
        }

        @Test
        void logsWarnWithoutTheExceptionText_whenTheBodyCannotBeRead() {
            // given
            HttpMessageNotReadableException unreadable = new HttpMessageNotReadableException(SECRET_DETAIL,
                    new MockHttpInputMessage(new byte[0]));

            // when
            advice.handleUnreadableBody(unreadable);

            // then
            assertThat(logged.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage()).contains("BAD_REQUEST").doesNotContain(SECRET_DETAIL);
            });
        }
    }

    // ── UnexpectedFailure ─────────────────────────────────────────────────────

    @Nested
    class UnexpectedFailure {

        @Test
        void answersInternalErrorWithoutTheExceptionText_whenAnythingElseFails() {
            // given
            IllegalStateException failure = new IllegalStateException(SECRET_DETAIL);

            // when
            ResponseEntity<byte[]> response = advice.handleUnexpectedFailure(failure);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getHeaders().getContentType()).isEqualTo(PLAIN_TEXT_UTF8);
            assertThat(textOf(response)).isEqualTo(EstError.INTERNAL_ERROR.text());
        }

        @Test
        void logsErrorWithTheException_whenAnythingElseFails() {
            // given
            IllegalStateException failure = new IllegalStateException(SECRET_DETAIL);

            // when
            advice.handleUnexpectedFailure(failure);

            // then
            assertThat(logged.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.ERROR);
                assertThat(event.getThrowableProxy().getMessage()).isEqualTo(SECRET_DETAIL);
            });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String textOf(ResponseEntity<byte[]> response) {
        return new String(Objects.requireNonNull(response.getBody()), StandardCharsets.UTF_8);
    }
}
