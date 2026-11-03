package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

class NativeSigningExceptionHandlingAdviceTest {

    private static final String OPERATOR_ONLY_DETAIL = "key 42";
    private static final String OPERATOR = "connector said: " + OPERATOR_ONLY_DETAIL + " locked";
    // Distinct from the advice's refusal fallback, so a response that drops the client message cannot pass.
    private static final String CLIENT = "The document does not satisfy the signing profile.";

    private final NativeSigningExceptionHandlingAdvice advice = new NativeSigningExceptionHandlingAdvice();

    @ParameterizedTest
    @EnumSource(value = SigningEngineFailure.class, names = {"INVALID_INPUT", "MALFORMED_INPUT"})
    void answers422WithClientMessageOnly_whenCallerInputIsRefused(SigningEngineFailure inputFailure) {
        // given — a failure carrying operator detail and a client message

        // when
        ResponseEntity<Object> response = handle(inputFailure);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
        assertThat(response.getBody()).isEqualTo(List.of(CLIENT));
        assertThat(String.valueOf(response.getBody())).doesNotContain(OPERATOR_ONLY_DETAIL);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
    }

    @ParameterizedTest
    @EnumSource(value = SigningEngineFailure.class, names = {"CONNECTOR_FAULT", "SIGNER_FAULT"})
    void answers502WithClientMessageOnly_whenConnectorOrSignerFails(SigningEngineFailure downstreamFault) {
        // given — a failure carrying operator detail and a client message

        // when
        ResponseEntity<Object> response = handle(downstreamFault);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage()).isEqualTo(CLIENT));
        assertThat(String.valueOf(response.getBody())).doesNotContain(OPERATOR_ONLY_DETAIL);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
    }

    @Test
    void answers503WithRetryAfter_whenUnreachableConnectorCausedSignerFault() {
        // given
        ConnectorCommunicationException unreachableConnector = createUnreachableConnectorException();

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.SIGNER_FAULT, unreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @Test
    void answers503WithRetryAfter_whenUnreachableConnectorIsDeeperInCauseChain() {
        // given
        var wrappedUnreachableConnector = new ConnectorException("formatting failed",
                createUnreachableConnectorException());

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.CONNECTOR_FAULT, wrappedUnreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @Test
    void answers502WithoutRetryAfter_whenConnectorRefusedTheCall() {
        // given
        var connectorRefusal = new ConnectorException("connector answered 500");

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.CONNECTOR_FAULT, connectorRefusal);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
    }

    @Test
    void keeps422WithoutRetryAfter_whenInvalidInputWrapsUnreachableConnector() {
        // given
        ConnectorCommunicationException unreachableConnector = createUnreachableConnectorException();

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.INVALID_INPUT, unreachableConnector);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
    }

    @Test
    void answers503WithRetryAfter_whenTimeIsUnavailable() {
        // given — a failure carrying operator detail and a client message

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.TIME_UNAVAILABLE);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("30");
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage()).isEqualTo(CLIENT));
    }

    @Test
    void answers503WithRetryAfter_whenConnectorCommunicationFails() {
        // given
        ConnectorCommunicationException unreachableConnector = createUnreachableConnectorException();

        // when
        ResponseEntity<Object> response = advice.handleConnectorCommunicationException(unreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @ParameterizedTest
    @EnumSource(value = SigningEngineFailure.class, names = {"MISCONFIGURED", "BINDING_VIOLATION", "STEP_FAILED"})
    void answers500WithClientMessageOnly_whenPlatformFails(SigningEngineFailure platformFailure) {
        // given — a failure carrying operator detail and a client message

        // when
        ResponseEntity<Object> response = handle(platformFailure);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage()).isEqualTo(CLIENT));
        assertThat(String.valueOf(response.getBody())).doesNotContain(OPERATOR_ONLY_DETAIL);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
    }

    @Test
    void answers422WithRefusalFallback_whenInputFailureHasNoClientMessage() {
        // given
        String noClientMessage = null;
        var refusal = new SigningEngineException(SigningEngineFailure.INVALID_INPUT, OPERATOR, noClientMessage);

        // when
        ResponseEntity<Object> response = advice.handleSigningEngineException(refusal);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
        assertThat(response.getBody()).isEqualTo(List.of("The request was refused."));
    }

    @Test
    void answers500WithInternalFallback_whenStepFailureHasNoClientMessage() {
        // given
        String noClientMessage = null;
        var stepFailure = new SigningEngineException(SigningEngineFailure.STEP_FAILED, OPERATOR, noClientMessage);

        // when
        ResponseEntity<Object> response = advice.handleSigningEngineException(stepFailure);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class,
                        body -> assertThat(body.getMessage()).isEqualTo("Internal signing error"));
    }

    @ParameterizedTest
    @EnumSource(SigningEngineFailure.class)
    void answersErrorStatusWithBody_whenAnyFailureOccurs(SigningEngineFailure failure) {
        // given — a failure carrying operator detail and a client message

        // when
        ResponseEntity<Object> response = handle(failure);

        // then
        assertThat(response.getStatusCode()).matches(HttpStatusCode::isError, "an error status");
        assertThat(response.getBody()).isNotNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<Object> handle(SigningEngineFailure failure) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, CLIENT));
    }

    private ResponseEntity<Object> handle(SigningEngineFailure failure, Throwable cause) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, cause, CLIENT));
    }

    private static ConnectorCommunicationException createUnreachableConnectorException() {
        return new ConnectorCommunicationException("connector at 10.0.0.5 refused", new RuntimeException("refused"),
                null);
    }

    private static void assertConnectorUnavailable(ResponseEntity<Object> response) {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("30");
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class,
                        body -> assertThat(body.getMessage()).isEqualTo("The connector is unavailable."));
    }
}
