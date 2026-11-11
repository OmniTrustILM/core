package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import io.netty.handler.timeout.ReadTimeoutException;
import java.net.ConnectException;
import java.net.URI;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class NativeSigningExceptionHandlingAdviceTest {

    private static final String OPERATOR_ONLY_DETAIL = "key 42";
    private static final String OPERATOR = "connector said: " + OPERATOR_ONLY_DETAIL + " locked";
    // Distinct from the advice's refusal fallback, so a response that drops the client message cannot pass.
    private static final String CLIENT = "The document does not satisfy the signing profile.";
    private static final String CONNECTOR_TEXT = "connector at 10.0.0.5 answered text/html";

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
        var refusedConnection = new ConnectException("Connection refused");
        ConnectorCommunicationException unreachableConnector = createCommunicationFailure(refusedConnection);

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.SIGNER_FAULT, unreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @Test
    void answers503WithRetryAfter_whenUnreachableConnectorIsDeeperInCauseChain() {
        // given
        var noAnswerInTime = new TimeoutException("no answer within 30s");
        var wrappedUnreachableConnector = new ConnectorException("formatting failed",
                createCommunicationFailure(noAnswerInTime));

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.CONNECTOR_FAULT, wrappedUnreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @Test
    void answers502WithoutRetryAfter_whenSignerFaultWrapsUnreadableConnectorResponse() {
        // given
        var unreadableBody = new IllegalArgumentException("Cannot deserialize value of type SignatureDto");
        ConnectorCommunicationException unreadableResponse = createCommunicationFailure(unreadableBody);

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.SIGNER_FAULT, unreadableResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage()).isEqualTo(CLIENT));
    }

    @Test
    void answers502WithoutRetryAfter_whenConnectorFaultWrapsCommunicationFailureWithoutCause() {
        // given
        var unexpectedContentType = new ConnectorCommunicationException(CONNECTOR_TEXT, null);

        // when
        ResponseEntity<Object> response = handle(SigningEngineFailure.CONNECTOR_FAULT, unexpectedContentType);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage()).isEqualTo(CLIENT));
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
        var refusedConnection = new ConnectException("Connection refused");
        ConnectorCommunicationException unreachableConnector = createCommunicationFailure(refusedConnection);

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
        var refusedConnection = new ConnectException("Connection refused");
        ConnectorCommunicationException unreachableConnector = createCommunicationFailure(refusedConnection);

        // when
        ResponseEntity<Object> response = advice.handleConnectorCommunicationException(unreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @ParameterizedTest
    @MethodSource("transportFailures")
    void answers503WithRetryAfter_whenTransportFailureCausedCommunicationFailure(Throwable transportFailure) {
        // given
        ConnectorCommunicationException unreachableConnector = createCommunicationFailure(transportFailure);

        // when
        ResponseEntity<Object> response = advice.handleConnectorCommunicationException(unreachableConnector);

        // then
        assertConnectorUnavailable(response);
    }

    @Test
    void answers502WithFixedMessage_whenCommunicationFailureHasNoCause() {
        // given
        var unexpectedContentType = new ConnectorCommunicationException(CONNECTOR_TEXT, null);

        // when
        ResponseEntity<Object> response = advice.handleConnectorCommunicationException(unexpectedContentType);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage())
                        .isEqualTo("The connector returned a response that could not be used."));
        assertThat(String.valueOf(response.getBody())).doesNotContain(CONNECTOR_TEXT);
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

    @Test
    void answers422NamingTheItem_whenRefusalOccurredOnAnItem() {
        // given
        var failedItem = "doc-2";
        SigningEngineException refusal = new SigningEngineException(SigningEngineFailure.INVALID_INPUT, OPERATOR,
                CLIENT).withItem(failedItem);

        // when
        ResponseEntity<Object> response = advice.handleSigningEngineException(refusal);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
        assertThat(response.getBody()).isEqualTo(List.of("Item '" + failedItem + "': " + CLIENT));
    }

    @Test
    void answers502NamingTheItem_whenSignerFaultOccurredOnAnItem() {
        // given
        var failedItem = "doc-2";
        SigningEngineException signerFault = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, OPERATOR,
                CLIENT).withItem(failedItem);

        // when
        ResponseEntity<Object> response = advice.handleSigningEngineException(signerFault);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class,
                        body -> assertThat(body.getMessage()).isEqualTo("Item '" + failedItem + "': " + CLIENT));
    }

    @Test
    void answers503NamingTheItem_whenConnectorWasUnreachableForAnItem() {
        // given
        var failedItem = "doc-2";
        ConnectorCommunicationException unreachableConnector = createCommunicationFailure(
                new ConnectException("Connection refused"));
        SigningEngineException signerFault = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, OPERATOR,
                unreachableConnector, CLIENT).withItem(failedItem);

        // when
        ResponseEntity<Object> response = advice.handleSigningEngineException(signerFault);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class, body -> assertThat(body.getMessage())
                        .isEqualTo("Item '" + failedItem + "': The connector is unavailable."));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<Object> handle(SigningEngineFailure failure) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, CLIENT));
    }

    private ResponseEntity<Object> handle(SigningEngineFailure failure, Throwable cause) {
        return advice.handleSigningEngineException(new SigningEngineException(failure, OPERATOR, cause, CLIENT));
    }

    private static ConnectorCommunicationException createCommunicationFailure(Throwable cause) {
        return new ConnectorCommunicationException("connector at 10.0.0.5 refused", cause, null);
    }

    private static Stream<Named<Throwable>> transportFailures() {
        var connectorUri = URI.create("https://connector.example/v1/sign");
        return Stream
                .of(named("connection refused", new ConnectException("Connection refused")),
                        named("request failed",
                                new WebClientRequestException(new ConnectException("refused"), HttpMethod.POST,
                                        connectorUri, new HttpHeaders())),
                        named("no answer in time", new TimeoutException("no answer within 30s")),
                        named("read timed out", ReadTimeoutException.INSTANCE),
                        named("interrupted while waiting", new InterruptedException()),
                        named("connection pool exhausted", new PoolAcquirePendingLimitException()));
    }

    private static void assertConnectorUnavailable(ResponseEntity<Object> response) {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("30");
        assertThat(response.getBody())
                .isInstanceOfSatisfying(ErrorMessageDto.class,
                        body -> assertThat(body.getMessage()).isEqualTo("The connector is unavailable."));
    }

    /** Stands in for reactor-netty's shaded pool exception, which the advice recognises by its simple name. */
    private static final class PoolAcquirePendingLimitException extends RuntimeException {
    }
}
