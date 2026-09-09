package com.otilm.core.api;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ResponseStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The three deliberately-unchanged neighbor handlers are pinned alongside the translation rows so the change provably
 * touches only its own handlers.
 */
class ExceptionHandlingAdviceConnectorTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    private static ConnectorProblemException problem(int status, String title) {
        ProblemDetailExtended pd = new ProblemDetailExtended();
        pd.setStatus(status);
        pd.setTitle(title);
        pd.setDetail(title);
        pd.setRetryable(false);
        return new ConnectorProblemException(pd);
    }

    private static int annotatedStatus(String handlerMethod, Class<?> exceptionType) throws NoSuchMethodException {
        ResponseStatus annotation = ExceptionHandlingAdvice.class
                .getMethod(handlerMethod, exceptionType)
                .getAnnotation(ResponseStatus.class);
        assertNotNull(annotation, handlerMethod + " must declare @ResponseStatus");
        return annotation.value().value();
    }

    @Test
    void connectorProblem401BecomesBadGateway() {
        ResponseEntity<ErrorMessageDto> response = advice
                .handleConnectorProblemException(problem(401, "Credentials invalid"));
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().getMessage().contains("Original response code 401"));
    }

    @Test
    void connectorProblem403BecomesBadGateway() {
        assertEquals(HttpStatus.BAD_GATEWAY,
                advice.handleConnectorProblemException(problem(403, "Forbidden")).getStatusCode());
    }

    @Test
    void connectorProblem500BecomesBadGateway() {
        assertEquals(HttpStatus.BAD_GATEWAY,
                advice.handleConnectorProblemException(problem(500, "boom")).getStatusCode());
    }

    @Test
    void connectorProblem599BecomesBadGateway() {
        assertEquals(HttpStatus.BAD_GATEWAY,
                advice.handleConnectorProblemException(problem(599, "odd")).getStatusCode());
    }

    @Test
    void connectorProblem303BecomesBadGateway() {
        assertEquals(HttpStatus.BAD_GATEWAY,
                advice.handleConnectorProblemException(problem(303, "odd redirect")).getStatusCode());
    }

    @Test
    void connectorProblem400StaysVerbatim() {
        assertEquals(HttpStatus.BAD_REQUEST,
                advice.handleConnectorProblemException(problem(400, "malformed")).getStatusCode());
    }

    @Test
    void connectorProblem404StaysVerbatim() {
        assertEquals(HttpStatus.NOT_FOUND,
                advice.handleConnectorProblemException(problem(404, "not tracked")).getStatusCode());
    }

    @Test
    void connectorProblem499StaysVerbatim() {
        assertEquals(499,
                advice.handleConnectorProblemException(problem(499, "client closed")).getStatusCode().value());
    }

    @Test
    void connectorProblem422StaysVerbatim() {
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY,
                advice.handleConnectorProblemException(problem(422, "rejected")).getStatusCode());
    }

    @Test
    void translatedResponseKeepsOriginalMessage() {
        ResponseEntity<ErrorMessageDto> response = advice
                .handleConnectorProblemException(problem(401, "Credentials invalid"));
        assertNotNull(response.getBody());
        assertTrue(response.getBody().getMessage().contains("Credentials invalid"));
    }

    @Test
    void legacyConnector401BecomesBadGateway() {
        ResponseEntity<ErrorMessageDto> response = advice
                .handleConnectorClientException(new ConnectorClientException("denied", HttpStatus.UNAUTHORIZED));
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().getMessage().contains("Original response code 401"));
    }

    @Test
    void legacyConnector403BecomesBadGateway() {
        assertEquals(HttpStatus.BAD_GATEWAY,
                advice
                        .handleConnectorClientException(new ConnectorClientException("no", HttpStatus.FORBIDDEN))
                        .getStatusCode());
    }

    @Test
    void legacyConnector409StaysBadRequest() {
        assertEquals(HttpStatus.BAD_REQUEST,
                advice
                        .handleConnectorClientException(new ConnectorClientException("dup", HttpStatus.CONFLICT))
                        .getStatusCode());
    }

    @Test
    void legacyConnectorNullStatusStaysBadRequest() {
        ResponseEntity<ErrorMessageDto> response = advice
                .handleConnectorClientException(new ConnectorClientException("x", (HttpStatus) null));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessage().contains("Original response code"));
    }

    @Test
    void problemPathEmitsNumericOnlyStatusSuffix() {
        ResponseEntity<ErrorMessageDto> response = advice.handleConnectorProblemException(problem(401, "denied"));
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessage().contains("UNAUTHORIZED"),
                "problem path must append the numeric code only");
    }

    @Test
    void legacyPathEmitsNumericOnlyStatusSuffix() {
        ResponseEntity<ErrorMessageDto> translated = advice
                .handleConnectorClientException(new ConnectorClientException("denied", HttpStatus.UNAUTHORIZED));
        assertNotNull(translated.getBody());
        assertFalse(translated.getBody().getMessage().contains("UNAUTHORIZED"),
                "legacy path must append the numeric code only");

        ResponseEntity<ErrorMessageDto> untranslated = advice
                .handleConnectorClientException(new ConnectorClientException("dup", HttpStatus.CONFLICT));
        assertNotNull(untranslated.getBody());
        assertTrue(untranslated.getBody().getMessage().contains("Original response code 409"),
                "untranslated rows keep the suffix");
        assertFalse(untranslated.getBody().getMessage().contains("CONFLICT"),
                "untranslated rows use the numeric form too");
    }

    @Test
    void problemPathLogsServerErrorsAtErrorAndAuthAtWarn() {
        ListAppender<ILoggingEvent> logged = captureLogsOfAdvice();
        advice.handleConnectorProblemException(problem(500, "boom"));
        advice.handleConnectorProblemException(problem(401, "denied"));
        assertEquals(2, logged.list.size(), "each handled problem logs exactly once");
        assertEquals(Level.ERROR, logged.list.get(0).getLevel(), "a connector 500 must log at ERROR");
        assertEquals(Level.WARN, logged.list.get(1).getLevel(), "a connector 401 must log at WARN");
    }

    @Test
    void legacyPathLogsTranslatedAtWarnAndUntranslatedAtInfo() {
        ListAppender<ILoggingEvent> logged = captureLogsOfAdvice();
        advice.handleConnectorClientException(new ConnectorClientException("denied", HttpStatus.UNAUTHORIZED));
        advice.handleConnectorClientException(new ConnectorClientException("dup", HttpStatus.CONFLICT));
        assertEquals(2, logged.list.size(), "each handled failure logs exactly once");
        assertEquals(Level.WARN, logged.list.get(0).getLevel(), "a translated legacy 401 must log at WARN");
        assertEquals(Level.INFO, logged.list.get(1).getLevel(), "an untranslated legacy 409 must stay at INFO");
    }

    private static ListAppender<ILoggingEvent> captureLogsOfAdvice() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(ExceptionHandlingAdvice.class);
        logger.setLevel(Level.DEBUG);
        logger.addAppender(appender);
        return appender;
    }

    @Test
    void connectorServerExceptionStaysBadGateway() throws NoSuchMethodException {
        assertEquals(HttpStatus.BAD_GATEWAY.value(), annotatedStatus("handleConnectorServerException",
                com.otilm.api.exception.ConnectorServerException.class));
    }

    @Test
    void connectorCommunicationExceptionStaysServiceUnavailable() throws NoSuchMethodException {
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE.value(), annotatedStatus("handleConnectorCommunicationException",
                com.otilm.api.exception.ConnectorCommunicationException.class));
    }

    @Test
    void connectorEntityNotFoundStaysNotFound() throws NoSuchMethodException {
        assertEquals(HttpStatus.NOT_FOUND.value(), annotatedStatus("handleConnectorEntityNotFoundException",
                com.otilm.api.exception.ConnectorEntityNotFoundException.class));
    }
}
