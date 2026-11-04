package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.reactive.function.client.WebClientRequestException;

/**
 * Maps native signing failures to HTTP statuses for the native controller only. The body carries the wire-safe client
 * message and never connector text, so a connector's wording cannot reach the caller. The signing engines log every
 * failure they throw, so this advice logs them at debug level only.
 */
@RestControllerAdvice(assignableTypes = NativeSigningControllerImpl.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class NativeSigningExceptionHandlingAdvice {

    public static final int RETRY_AFTER_SECONDS = 30;

    private static final String REFUSED_FALLBACK = "The request was refused.";
    private static final String INTERNAL_FALLBACK = "Internal signing error";
    private static final String CONNECTOR_UNAVAILABLE = "The connector is unavailable.";
    private static final String UNUSABLE_RESPONSE = "The connector returned a response that could not be used.";

    private static final List<Class<? extends Throwable>> TRANSPORT_FAILURES = List
            .of(IOException.class, WebClientRequestException.class, TimeoutException.class,
                    io.netty.handler.timeout.TimeoutException.class, InterruptedException.class);
    private static final String POOL_ACQUIRE_EXHAUSTED = "PoolAcquirePendingLimitException";

    private static final Logger LOG = LoggerFactory.getLogger(NativeSigningExceptionHandlingAdvice.class);

    @ExceptionHandler(SigningEngineException.class)
    public ResponseEntity<Object> handleSigningEngineException(SigningEngineException ex) {
        SigningEngineFailure failure = ex.failure();
        LOG.debug("Native signing failed: {} {}", failure, ex.operatorMessage());
        boolean callerFault = failure == SigningEngineFailure.INVALID_INPUT
                || failure == SigningEngineFailure.MALFORMED_INPUT;
        // The signer and formatting clients wrap an unreachable connector in a fault of their own.
        if (!callerFault && isConnectorOutage(ex)) {
            return serviceUnavailable(CONNECTOR_UNAVAILABLE);
        }
        String message = ex.getMessage();
        String clientMessage = message != null ? message : REFUSED_FALLBACK;
        String errorMessage = message != null ? message : INTERNAL_FALLBACK;
        return switch (failure) {
            case INVALID_INPUT, MALFORMED_INPUT -> ResponseEntity.unprocessableContent().body(List.of(clientMessage));
            case CONNECTOR_FAULT, SIGNER_FAULT ->
                ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(ErrorMessageDto.getInstance(errorMessage));
            case TIME_UNAVAILABLE -> serviceUnavailable(errorMessage);
            case MISCONFIGURED, BINDING_VIOLATION, STEP_FAILED ->
                ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ErrorMessageDto.getInstance(errorMessage));
        };
    }

    @ExceptionHandler(ConnectorCommunicationException.class)
    public ResponseEntity<Object> handleConnectorCommunicationException(ConnectorCommunicationException ex) {
        if (isConnectorOutage(ex)) {
            LOG.warn("Native signing connector unavailable: {}", ex.getMessage());
            return serviceUnavailable(CONNECTOR_UNAVAILABLE);
        }
        LOG.warn("Native signing connector response unusable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(ErrorMessageDto.getInstance(UNUSABLE_RESPONSE));
    }

    /**
     * A connector is out only when a {@link ConnectorCommunicationException} in the chain was caused by the transport:
     * the connection, a timeout, an interruption or an exhausted connection pool, which a retry may get past. The same
     * exception also reports a response that could not be read, which a retry would only repeat. The pool's exception
     * is matched by name, as the connector client matches it, because its type is shaded inside reactor-netty.
     */
    @SuppressWarnings("java:S1872")
    private static boolean isConnectorOutage(Throwable failure) {
        return ExceptionUtils
                .getThrowableList(failure)
                .stream()
                .filter(ConnectorCommunicationException.class::isInstance)
                .map(Throwable::getCause)
                .filter(Objects::nonNull)
                .anyMatch(cause -> TRANSPORT_FAILURES.stream().anyMatch(type -> type.isInstance(cause))
                        || POOL_ACQUIRE_EXHAUSTED.equals(cause.getClass().getSimpleName()));
    }

    private static ResponseEntity<Object> serviceUnavailable(String message) {
        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(RETRY_AFTER_SECONDS))
                .body(ErrorMessageDto.getInstance(message));
    }
}
