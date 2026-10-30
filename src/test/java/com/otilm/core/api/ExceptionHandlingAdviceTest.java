package com.otilm.core.api;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.model.common.ErrorMessageDto;
import java.sql.SQLException;
import java.util.List;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExceptionHandlingAdviceTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    @Test
    void handleCbomRepositoryException_ShouldUseProblemDetailDetailWhenPresent() {
        ProblemDetail problemDetail = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, "version must be an integer");
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("version must be an integer", response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldFallbackToExceptionMessageWhenDetailIsBlank() {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setDetail("");
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ex.getMessage(), response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldFallbackToExceptionMessageWhenDetailIsNull() {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setDetail(null);
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ex.getMessage(), response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldReturnInternalServerErrorWhenProblemDetailIsNull() {
        CbomRepositoryException ex = new CbomRepositoryException("Upload of BOM failed.");

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Upload of BOM failed.", response.getBody().getMessage());
    }

    @Test
    void handleCertificateRequestException_ShouldNotFailWhenCauseIsNull() {
        CertificateRequestException ex = new CertificateRequestException("Invalid CSR");

        ErrorMessageDto response = advice.handleCertificateRequestException(ex);

        assertNotNull(response);
        assertEquals("Invalid CSR", response.getMessage());
    }

    @Test
    void handleCertificateRequestException_ShouldNotExposeCauseInResponse() {
        CertificateRequestException ex = new CertificateRequestException("Invalid CSR",
                new IllegalArgumentException("bad encoding"));

        ErrorMessageDto response = advice.handleCertificateRequestException(ex);

        assertEquals("Invalid CSR", response.getMessage());
    }

    @Test
    void handleIllegalArgumentException_ShouldNotExposeTheExceptionMessage() {
        IllegalArgumentException ex = new IllegalArgumentException(
                "Java 8 date/time type `java.time.ZonedDateTime` not supported by default (through reference chain: "
                        + "java.util.ArrayList[0]->DateTimeAttributeContentV3[\"data\"])");

        ErrorMessageDto response = advice.handleIllegalArgumentException(ex);

        assertEquals("The request could not be processed.", response.getMessage());
    }

    @Test
    void handleMethodArgumentNotValidException_ShouldReturnStringArray() throws NoSuchMethodException {
        BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new Object(), "request");
        binding.addError(new FieldError("request", "name", "must not be blank"));
        MethodParameter parameter = new MethodParameter(
                ExceptionHandlingAdviceTest.class.getDeclaredMethod("dummy", String.class), 0);
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, binding);

        List<String> response = advice.handleMethodArgumentNotValidException(ex);

        assertEquals(List.of("name must not be blank"), response);
    }

    @SuppressWarnings("unused")
    private void dummy(String s) {
        // Target for the MethodParameter used to build a MethodArgumentNotValidException above.
    }

    /**
     * A realistic driver chain. The refused row's value travels inside the server's {@code DETAIL} line, which is what
     * makes this a disclosure rather than a diagnostic: no fence in this codebase can see it, because they scan source
     * text for the key's spelling and here the value is assembled at runtime by the driver.
     *
     * <p>
     * The constant is named for what it is -- a planted token this test looks for in the log -- rather than for the
     * column it stands in for. Naming it after the key would declare that vocabulary in a client-facing package, which
     * {@code IdentityKeyExposureFenceArchTest} refuses, and rightly: the fence cannot tell a fixture from a leak.
     */
    private static final String POISONED_ROW_VALUE = "9f2c1d4e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";

    private static final String POISONED_DRIVER_MESSAGE = """
            ERROR: duplicate key value violates unique constraint "uq_crypto_asset_identity_key"
              Detail: Key (identity_key)=(""" + POISONED_ROW_VALUE + """
            ) already exists.""";

    /** A body the parser could not read may carry a secret, and the parser's message quotes the token it stopped at. */
    @Test
    void anUnreadableBodyIsLoggedWithoutTheParsersWords() {
        ListAppender<ILoggingEvent> logged = captureLogsOfAdvice();
        JsonProcessingException parserFailure = assertThrows(JsonProcessingException.class,
                () -> new ObjectMapper().readTree("{\"passphrase\": correct horse battery staple}"));
        HttpMessageNotReadableException unreadable = new HttpMessageNotReadableException(
                "JSON parse error: " + parserFailure.getMessage(), parserFailure,
                new MockHttpInputMessage(new byte[0]));

        ErrorMessageDto response = advice.handleMessageNotReadable(unreadable);

        assertEquals("Unable to read HTTP message", response.getMessage());
        assertTrue(logged.list.stream().anyMatch(event -> event.getFormattedMessage().contains("line 1, column")),
                "the parse location keeps the failure diagnosable");
        for (ILoggingEvent event : logged.list) {
            assertFalse(renderedFully(event).contains("correct"), renderedFully(event));
        }
    }

    private static DataIntegrityViolationException poisonedFailure() {
        ConstraintViolationException hibernateFailure = new ConstraintViolationException(POISONED_DRIVER_MESSAGE,
                new SQLException(POISONED_DRIVER_MESSAGE, "23505"), "uq_crypto_asset_identity_key");
        return new DataIntegrityViolationException(POISONED_DRIVER_MESSAGE, hibernateFailure);
    }

    private static ListAppender<ILoggingEvent> captureLogsOfAdvice() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(ExceptionHandlingAdvice.class);
        // The full-throwable line is a debug line, and the surrounding configuration need not be emitting those.
        logger.setLevel(Level.DEBUG);
        logger.addAppender(appender);
        return appender;
    }

    /**
     * The whole point of the handler: what an operator's ERROR-level log carries must not include the row the database
     * refused. DEBUG deliberately still carries the throwable, so the assertion is scoped to ERROR rather than to every
     * event.
     */
    @Test
    void aDatabaseIntegrityViolationIsLoggedAtErrorWithoutTheFailingRow() {
        ListAppender<ILoggingEvent> logged = captureLogsOfAdvice();

        ErrorMessageDto response = advice.handleDataIntegrityViolation(poisonedFailure());

        assertEquals("Internal server error.", response.getMessage());

        List<ILoggingEvent> errors = logged.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
        assertFalse(errors.isEmpty(), "the failure must still be reported at ERROR");
        for (ILoggingEvent error : errors) {
            assertFalse(renderedFully(error).contains(POISONED_ROW_VALUE),
                    "an ERROR line carried the identity key: " + renderedFully(error));
            assertFalse(renderedFully(error).contains("Detail:"),
                    "an ERROR line carried the driver's DETAIL: " + renderedFully(error));
        }
    }

    @Test
    void aDatabaseIntegrityViolationNamesTheConstraintSoItStaysDiagnosable() {
        ListAppender<ILoggingEvent> logged = captureLogsOfAdvice();

        advice.handleDataIntegrityViolation(poisonedFailure());

        assertTrue(
                logged.list
                        .stream()
                        .filter(event -> event.getLevel() == Level.ERROR)
                        .anyMatch(event -> event.getFormattedMessage().contains("uq_crypto_asset_identity_key")),
                "scrubbing the row must not cost the constraint name, which is the actionable datum");
    }

    /**
     * Renders the event the way an encoder would -- formatted message plus the whole throwable chain. Asserting only on
     * {@code getFormattedMessage()} would pass while the key sat in an attached stack trace, which is exactly how this
     * disclosure reached the log in the first place.
     */
    private static String renderedFully(ILoggingEvent event) {
        StringBuilder rendered = new StringBuilder(event.getFormattedMessage());
        for (IThrowableProxy proxy = event.getThrowableProxy(); proxy != null; proxy = proxy.getCause()) {
            rendered.append(' ').append(proxy.getClassName()).append(' ').append(proxy.getMessage());
        }
        return rendered.toString();
    }
}
