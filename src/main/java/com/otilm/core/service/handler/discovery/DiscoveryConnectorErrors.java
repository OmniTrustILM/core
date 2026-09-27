package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.core.service.handler.authority.ConnectorOperationErrorCodes;
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
