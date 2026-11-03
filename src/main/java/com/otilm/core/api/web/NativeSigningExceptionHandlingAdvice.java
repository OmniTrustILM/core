package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps native signing failures to HTTP statuses for the native controller only. The body carries the wire-safe client
 * message and never connector text, so a connector's wording cannot reach the caller.
 */
@RestControllerAdvice(assignableTypes = NativeSigningControllerImpl.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class NativeSigningExceptionHandlingAdvice {

    public static final int RETRY_AFTER_SECONDS = 30;

    private static final String REFUSED_FALLBACK = "The request was refused.";
    private static final String INTERNAL_FALLBACK = "Internal signing error";

    private static final Logger LOG = LoggerFactory.getLogger(NativeSigningExceptionHandlingAdvice.class);

    @ExceptionHandler(SigningEngineException.class)
    public ResponseEntity<Object> handleSigningEngineException(SigningEngineException ex) {
        String message = ex.getMessage();
        String clientMessage = message != null ? message : REFUSED_FALLBACK;
        String errorMessage = message != null ? message : INTERNAL_FALLBACK;
        return switch (ex.failure()) {
            case INVALID_INPUT, MALFORMED_INPUT -> ResponseEntity.unprocessableEntity().body(List.of(clientMessage));
            case CONNECTOR_FAULT, SIGNER_FAULT -> {
                LOG.warn("Native signing failed: {} {}", ex.failure(), ex.operatorMessage());
                yield ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(ErrorMessageDto.getInstance(errorMessage));
            }
            case TIME_UNAVAILABLE -> {
                LOG.warn("Native signing failed: {} {}", ex.failure(), ex.operatorMessage());
                yield ResponseEntity
                        .status(HttpStatus.SERVICE_UNAVAILABLE)
                        .header(HttpHeaders.RETRY_AFTER, String.valueOf(RETRY_AFTER_SECONDS))
                        .body(ErrorMessageDto.getInstance(errorMessage));
            }
            default -> {
                LOG.error("Native signing failed: {} {}", ex.failure(), ex.operatorMessage(), ex);
                yield ResponseEntity
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ErrorMessageDto.getInstance(errorMessage));
            }
        };
    }

    @ExceptionHandler(ConnectorCommunicationException.class)
    public ResponseEntity<ErrorMessageDto> handleConnectorCommunicationException(ConnectorCommunicationException ex) {
        LOG.warn("Native signing connector unavailable: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(RETRY_AFTER_SECONDS))
                .body(ErrorMessageDto.getInstance("The connector is unavailable."));
    }
}
