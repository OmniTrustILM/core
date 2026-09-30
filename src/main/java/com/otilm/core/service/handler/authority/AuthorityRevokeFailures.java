package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * Core-authored text for a revocation the authority did not carry out, safe for the certificate history and the error
 * an operator reads. A connector's own message can name its exception classes and upstream internals, so it stays in
 * the log. A connector's legacy 422 arrives as a {@link ValidationException} carrying the validation messages the
 * contract has it return, which pass through.
 */
public final class AuthorityRevokeFailures {

    private static final String UNREACHABLE = "the authority could not be reached";
    private static final String REFUSED_CREDENTIALS = "the authority refused Core's credentials";
    private static final String ERROR = "the authority reported an error";
    private static final String REJECTED = "the authority rejected the revocation";

    private AuthorityRevokeFailures() {
    }

    public static String describe(Exception e) {
        return switch (e) {
            case ConnectorCommunicationException ignored -> UNREACHABLE;
            case ConnectorProblemException problem when problem.getProblemDetail() != null ->
                describe(problem.getProblemDetail().getErrorCode(),
                        HttpStatus.resolve(problem.getProblemDetail().getStatus()));
            case ConnectorClientException client -> describe(client.getHttpStatus());
            case ConnectorServerException server -> describe(server.getHttpStatus());
            case ConnectorException ignored -> REJECTED;
            case CertificateOperationException known when known.getMessage() != null -> known.getMessage();
            case ValidationException known when known.getMessage() != null -> known.getMessage();
            default -> "revocation failed";
        };
    }

    /**
     * Names a connector failure for the log by its class and HTTP status. Its message and cause stay out: they can
     * quote the connector's answer, which may carry credentials the request sent.
     */
    public static String logDetail(ConnectorException e) {
        HttpStatus status = switch (e) {
            case ConnectorProblemException problem when problem.getProblemDetail() != null ->
                HttpStatus.resolve(problem.getProblemDetail().getStatus());
            case ConnectorClientException client -> client.getHttpStatus();
            case ConnectorServerException server -> server.getHttpStatus();
            default -> null;
        };
        String type = e.getClass().getSimpleName();
        return status == null ? type : "%s, HTTP %d".formatted(type, status.value());
    }

    /** The error code decides where it has a meaning of its own; otherwise the problem's status does. */
    private static String describe(ErrorCode code, HttpStatus status) {
        return switch (code) {
            case SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, REQUEST_TIMEOUT -> UNREACHABLE;
            case UNAUTHORIZED, FORBIDDEN, CREDENTIAL_INVALID -> REFUSED_CREDENTIALS;
            case INTERNAL_SERVER_ERROR, UPSTREAM_ERROR, RATE_LIMIT_EXCEEDED -> ERROR;
            case REVOCATION_NOT_ALLOWED, POLICY_VIOLATION, VALIDATION_FAILED, CERTIFICATE_MISMATCH -> REJECTED;
            case null, default -> describe(status);
        };
    }

    private static String describe(HttpStatus status) {
        if (status == null) {
            return REJECTED;
        }
        return switch (status) {
            case BAD_GATEWAY, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, REQUEST_TIMEOUT -> UNREACHABLE;
            case UNAUTHORIZED, FORBIDDEN -> REFUSED_CREDENTIALS;
            default -> status.is5xxServerError() ? ERROR : REJECTED;
        };
    }
}
