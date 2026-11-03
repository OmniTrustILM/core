package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class NativeSigningExceptionHandlingAdviceTest {

    private static final String OPERATOR = "connector said: key 42 locked";
    private static final String CLIENT = "The request was refused.";

    private final NativeSigningExceptionHandlingAdvice advice = new NativeSigningExceptionHandlingAdvice();

    private ResponseEntity<Object> handle(SigningEngineFailure failure) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, CLIENT));
    }

    private ResponseEntity<Object> handle(SigningEngineFailure failure, Throwable cause) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, cause, CLIENT));
    }

    private static ConnectorCommunicationException unreachableConnector() {
        return new ConnectorCommunicationException("connector at 10.0.0.5 refused", new RuntimeException("refused"),
                null);
    }

    private static void assertConnectorUnavailable(ResponseEntity<Object> response) {
        Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        Assertions.assertEquals("30", response.getHeaders().getFirst("Retry-After"));
        Assertions.assertEquals("The connector is unavailable.", ((ErrorMessageDto) response.getBody()).getMessage());
    }

    @Test
    void mapsInvalidAndMalformedInputTo422WithTheClientMessageOnly() {
        for (SigningEngineFailure failure : List
                .of(SigningEngineFailure.INVALID_INPUT, SigningEngineFailure.MALFORMED_INPUT)) {
            ResponseEntity<Object> response = handle(failure);
            Assertions.assertEquals(HttpStatus.UNPROCESSABLE_CONTENT, response.getStatusCode());
            Assertions.assertEquals(List.of(CLIENT), response.getBody());
            Assertions.assertFalse(String.valueOf(response.getBody()).contains("key 42"));
            Assertions.assertNull(response.getHeaders().getFirst("Retry-After"));
        }
    }

    @Test
    void mapsConnectorAndSignerFaultsTo502() {
        for (SigningEngineFailure failure : List
                .of(SigningEngineFailure.CONNECTOR_FAULT, SigningEngineFailure.SIGNER_FAULT)) {
            ResponseEntity<Object> response = handle(failure);
            Assertions.assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
            Assertions.assertEquals(CLIENT, ((ErrorMessageDto) response.getBody()).getMessage());
            Assertions.assertFalse(String.valueOf(response.getBody()).contains("key 42"));
            Assertions.assertNull(response.getHeaders().getFirst("Retry-After"));
        }
    }

    @Test
    void mapsASignerFaultCausedByAnUnreachableConnectorTo503WithRetryAfter() {
        assertConnectorUnavailable(handle(SigningEngineFailure.SIGNER_FAULT, unreachableConnector()));
    }

    @Test
    void mapsAConnectorFaultWithAnUnreachableConnectorDeeperInTheChainTo503WithRetryAfter() {
        ConnectorException wrapped = new ConnectorException("formatting failed", unreachableConnector());

        assertConnectorUnavailable(handle(SigningEngineFailure.CONNECTOR_FAULT, wrapped));
    }

    @Test
    void mapsAConnectorFaultCausedByAConnectorRefusalTo502() {
        ResponseEntity<Object> response = handle(SigningEngineFailure.CONNECTOR_FAULT,
                new ConnectorException("connector answered 500"));

        Assertions.assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        Assertions.assertNull(response.getHeaders().getFirst("Retry-After"));
    }

    @Test
    void keepsInvalidInput422EvenWhenAnUnreachableConnectorIsInTheChain() {
        ResponseEntity<Object> response = handle(SigningEngineFailure.INVALID_INPUT, unreachableConnector());

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_CONTENT, response.getStatusCode());
        Assertions.assertNull(response.getHeaders().getFirst("Retry-After"));
    }

    @Test
    void mapsTimeUnavailableTo503WithRetryAfter() {
        ResponseEntity<Object> response = handle(SigningEngineFailure.TIME_UNAVAILABLE);
        Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        Assertions.assertEquals("30", response.getHeaders().getFirst("Retry-After"));
        Assertions.assertEquals(CLIENT, ((ErrorMessageDto) response.getBody()).getMessage());
    }

    @Test
    void mapsAnUnreachableConnectorTo503WithRetryAfter() {
        assertConnectorUnavailable(advice.handleConnectorCommunicationException(unreachableConnector()));
    }

    @Test
    void mapsEveryOtherFailureTo500() {
        for (SigningEngineFailure failure : List
                .of(SigningEngineFailure.MISCONFIGURED, SigningEngineFailure.BINDING_VIOLATION,
                        SigningEngineFailure.STEP_FAILED)) {
            ResponseEntity<Object> response = handle(failure);
            Assertions.assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            Assertions.assertEquals(CLIENT, ((ErrorMessageDto) response.getBody()).getMessage());
            Assertions.assertFalse(String.valueOf(response.getBody()).contains("key 42"));
            Assertions.assertNull(response.getHeaders().getFirst("Retry-After"));
        }
    }

    @Test
    void fallsBackWhenTheClientMessageIsNull() {
        ResponseEntity<Object> unprocessable = advice
                .handleSigningEngineException(
                        new SigningEngineException(SigningEngineFailure.INVALID_INPUT, OPERATOR, null));
        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_CONTENT, unprocessable.getStatusCode());
        Assertions.assertEquals(List.of("The request was refused."), unprocessable.getBody());

        ResponseEntity<Object> internal = advice
                .handleSigningEngineException(
                        new SigningEngineException(SigningEngineFailure.STEP_FAILED, OPERATOR, null));
        Assertions.assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, internal.getStatusCode());
        Assertions.assertEquals("Internal signing error", ((ErrorMessageDto) internal.getBody()).getMessage());
    }

    @Test
    void everyFailureHasAnErrorStatusAndABody() {
        for (SigningEngineFailure failure : SigningEngineFailure.values()) {
            ResponseEntity<Object> response = handle(failure);
            Assertions
                    .assertTrue(response.getStatusCode().isError(), failure + " answered " + response.getStatusCode());
            Assertions.assertNotNull(response.getBody(), failure + " answered without a body");
        }
    }
}
