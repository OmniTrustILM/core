package com.otilm.core.api.est;

import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstResponses;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders what is thrown while an EST request is handled as the plain text of an {@link EstError}, never as the JSON of
 * the platform. It is the one place that logs a refusal: at WARN with the realm and the error (never the detail), and
 * at ERROR with the exception when something unexpected failed. It goes before the platform's own advice, which answers
 * every exception.
 * <p>
 * It applies only once a handler method is chosen. A request that Spring refuses earlier is refused by the protocol
 * filter instead.
 */
@Slf4j
@RestControllerAdvice(assignableTypes = EstControllerImpl.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class EstExceptionHandlingAdvice {

    private static final String NO_REALM = "-";

    @ExceptionHandler(EstException.class)
    public ResponseEntity<byte[]> handleEstException(EstException exception) {
        Optional<String> realm = exception.realm();
        log.warn("EST request refused as {} for realm {}", exception.error(), realm.orElse(NO_REALM));
        return EstResponses
                .error(exception.error(), realm.orElse(EstResponses.DEFAULT_REALM), exception.detail().orElse(null));
    }

    /**
     * The body of the request could not be read, as when a required body is empty. Its text is not logged: it can hold
     * the client's content.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<byte[]> handleUnreadableBody(HttpMessageNotReadableException exception) {
        log.warn("EST request refused as {} for realm {}", EstError.BAD_REQUEST, NO_REALM);
        return EstResponses.error(EstError.BAD_REQUEST, EstResponses.DEFAULT_REALM);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<byte[]> handleUnexpectedFailure(Exception exception) {
        log.error("EST request failed", exception);
        return EstResponses.error(EstError.INTERNAL_ERROR, EstResponses.DEFAULT_REALM);
    }
}
