package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.core.service.handler.authority.ConnectorOperationErrorCodes;
import java.time.Duration;
import java.util.Optional;
import org.springframework.http.HttpStatus;

/**
 * Classification of connector failures shared by the discovery tick workers, so the status and drain paths cannot drift
 * on what counts as a definitive refusal.
 */
public final class DiscoveryConnectorErrors {

    private static final String UNANSWERED = "the connector did not answer";

    private DiscoveryConnectorErrors() {
    }

    /**
     * Text describing a connector failure that is safe to put on the run, where API clients read it.
     *
     * <p>
     * Only Core-authored text reaches the run's messages; the connector's {@code getMessage()} and its RFC 9457
     * {@code detail} stay in the log. The contract obliges a connector to curate that field, but an obligation is not a
     * guarantee, and the run's message is a user-visible surface whose own schema promises no provider, host or
     * transport internals. What survives is the error *code*, which is a closed vocabulary, mapped here to text Core
     * wrote.
     */
    public static String describe(Throwable e) {
        if (!(e instanceof ConnectorProblemException problem) || problem.getProblemDetail() == null) {
            return UNANSWERED;
        }
        return switch (problem.getProblemDetail().getErrorCode()) {
            case OPERATION_NOT_TRACKED -> "the connector no longer tracks the run";
            case VALIDATION_FAILED -> "the connector refused the run's configuration";
            case CHECKPOINT_LOST -> "the connector lost the run's checkpoint";
            case UNAUTHORIZED, FORBIDDEN, CREDENTIAL_INVALID -> "the connector refused Core's credentials";
            case SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, REQUEST_TIMEOUT -> "the connector was unreachable";
            case UPSTREAM_ERROR -> "the connector's own upstream failed";
            case RATE_LIMIT_EXCEEDED -> "the connector rate-limited Core";
            case INTERNAL_SERVER_ERROR -> "the connector reported an internal error";
            case null, default -> UNANSWERED;
        };
    }

    /**
     * True when the connector refused the run's configuration: a verdict on what was asked, which a retry repeats and
     * only whoever asked can correct.
     */
    public static boolean isConfigurationRefused(Throwable e) {
        return e instanceof ConnectorProblemException problem && problem.getProblemDetail() != null
                && problem.getProblemDetail().getErrorCode() == ErrorCode.VALIDATION_FAILED;
    }

    /**
     * True when the connector answered 422: it cannot do what was asked, and asking again repeats the answer. Over REST
     * the answer is a problem document, or a plain client error without one; the AMQP proxy turns a 422 into a
     * {@link ValidationException}.
     */
    public static boolean isRefusal(Throwable e) {
        if (e instanceof ValidationException) {
            return true;
        }
        if (e instanceof ConnectorClientException client) {
            return client.getHttpStatus() == HttpStatus.UNPROCESSABLE_ENTITY;
        }
        return answeredWith(e, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    /**
     * True when the connector answered 503: it is busy, and will answer later. Over REST the answer is a problem
     * document, or a server error without one, which is also what the AMQP proxy relays.
     */
    public static boolean isBusy(Throwable e) {
        if (e instanceof ConnectorServerException server) {
            return server.getHttpStatus() == HttpStatus.SERVICE_UNAVAILABLE;
        }
        return answeredWith(e, HttpStatus.SERVICE_UNAVAILABLE);
    }

    /**
     * When the connector asked to be called again, where its answer says so: the problem document's
     * {@code retryAfterSeconds}, which mirrors the {@code Retry-After} header no transport passes on.
     */
    public static Optional<Duration> retryAfter(Throwable e) {
        if (!(e instanceof ConnectorProblemException problem) || problem.getProblemDetail() == null) {
            return Optional.empty();
        }
        Integer seconds = problem.getProblemDetail().getRetryAfterSeconds();
        return seconds == null || seconds <= 0 ? Optional.empty() : Optional.of(Duration.ofSeconds(seconds));
    }

    private static boolean answeredWith(Throwable e, HttpStatus status) {
        return e instanceof ConnectorProblemException problem && problem.getProblemDetail() != null
                && problem.getProblemDetail().getStatus() == status.value();
    }

    /**
     * True when the connector says it no longer tracks the run — the contract's own definitive signal that retrying
     * cannot recover the run, which ends FAILED.
     *
     * <p>
     * The status gates the code rather than the reverse, since a code is trusted only on a 404; through an AMQP proxy
     * that drops the problem document the same condition arrives instead as a plain
     * {@link ConnectorEntityNotFoundException}.
     */
    public static boolean isRunNoLongerTracked(Throwable e) {
        if (e instanceof ConnectorProblemException problem) {
            ProblemDetailExtended detail = problem.getProblemDetail();
            return detail != null && detail.getStatus() == HttpStatus.NOT_FOUND.value()
                    && ConnectorOperationErrorCodes.isOperationNotTracked(detail.getErrorCode());
        }
        return e instanceof ConnectorEntityNotFoundException;
    }
}
