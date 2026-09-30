package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;

class AuthorityRevokeFailuresTest {

    private static final String UNREACHABLE = "the authority could not be reached";
    private static final String CREDENTIALS = "the authority refused Core's credentials";
    private static final String ERROR = "the authority reported an error";
    private static final String REJECTED = "the authority rejected the revocation";

    static Stream<Arguments> failures() {
        return Stream
                .of(Arguments.of(new ConnectorCommunicationException("Connection reset", null), UNREACHABLE),
                        Arguments.of(client(HttpStatus.UNAUTHORIZED), CREDENTIALS),
                        Arguments.of(client(HttpStatus.FORBIDDEN), CREDENTIALS),
                        Arguments.of(client(HttpStatus.REQUEST_TIMEOUT), UNREACHABLE),
                        Arguments.of(client(HttpStatus.BAD_REQUEST), REJECTED), Arguments.of(client(null), REJECTED),
                        Arguments.of(server(HttpStatus.INTERNAL_SERVER_ERROR), ERROR),
                        Arguments.of(server(HttpStatus.BAD_GATEWAY), UNREACHABLE),
                        Arguments.of(server(HttpStatus.SERVICE_UNAVAILABLE), UNREACHABLE),
                        Arguments.of(server(HttpStatus.GATEWAY_TIMEOUT), UNREACHABLE),
                        Arguments.of(problem(ErrorCode.UPSTREAM_ERROR, 502), ERROR),
                        Arguments.of(problem(ErrorCode.SERVICE_UNAVAILABLE, 503), UNREACHABLE),
                        Arguments.of(problem(ErrorCode.CREDENTIAL_INVALID, 422), CREDENTIALS),
                        Arguments.of(problem(ErrorCode.REVOCATION_NOT_ALLOWED, 422), REJECTED),
                        Arguments.of(problem(ErrorCode.VALIDATION_FAILED, 422), REJECTED),
                        Arguments.of(problem(null, 503), UNREACHABLE), Arguments.of(problem(null, 401), CREDENTIALS),
                        Arguments.of(problem(ErrorCode.RESOURCE_NOT_FOUND, 404), REJECTED),
                        Arguments.of(problem(null, 0), REJECTED),
                        Arguments.of(new ConnectorEntityNotFoundException("Certificate not found"), REJECTED),
                        Arguments.of(new ConnectorException("Connector not found for authority instance"), REJECTED),
                        Arguments
                                .of(new IllegalStateException("java.lang.NullPointerException at line 42"),
                                        "revocation failed"));
    }

    @ParameterizedTest
    @MethodSource("failures")
    void describesTheFailureInCoreText(Exception failure, String expected) {
        Assertions.assertEquals(expected, AuthorityRevokeFailures.describe(failure));
    }

    @ParameterizedTest
    @MethodSource("coreAuthored")
    void keepsTheTextOfCoreAuthoredFailures(Exception failure) {
        Assertions.assertEquals(failure.getMessage(), AuthorityRevokeFailures.describe(failure));
    }

    static Stream<Exception> coreAuthored() {
        return Stream
                .of(new ValidationException("Revocation reason is not allowed"),
                        new CertificateOperationException("Certificate has no content"));
    }

    static Stream<Arguments> logDetails() {
        return Stream
                .of(Arguments.of(server(HttpStatus.INTERNAL_SERVER_ERROR), "ConnectorServerException, HTTP 500"),
                        Arguments.of(client(HttpStatus.UNAUTHORIZED), "ConnectorClientException, HTTP 401"),
                        Arguments.of(client(null), "ConnectorClientException"),
                        Arguments.of(problem(ErrorCode.UPSTREAM_ERROR, 502), "ConnectorProblemException, HTTP 502"),
                        Arguments.of(problem(null, 0), "ConnectorProblemException"),
                        Arguments
                                .of(new ConnectorCommunicationException("Connection reset", null),
                                        "ConnectorCommunicationException"));
    }

    @ParameterizedTest
    @MethodSource("logDetails")
    void namesTheFailureForTheLogWithoutItsMessage(ConnectorException failure, String expected) {
        Assertions.assertEquals(expected, AuthorityRevokeFailures.logDetail(failure));
    }

    private static ConnectorClientException client(HttpStatus status) {
        return new ConnectorClientException("java.lang.IllegalStateException: refused", status);
    }

    private static ConnectorServerException server(HttpStatus status) {
        return new ConnectorServerException("java.lang.IllegalStateException: failed", status);
    }

    private static ConnectorProblemException problem(ErrorCode code, int status) {
        ProblemDetailExtended detail = new ProblemDetailExtended();
        detail.setStatus(status);
        detail.setTitle("Problem");
        detail.setDetail("EJBCA at 10.0.0.5:8443 answered a SOAP fault");
        detail.setErrorCode(code);
        return new ConnectorProblemException(detail);
    }
}
