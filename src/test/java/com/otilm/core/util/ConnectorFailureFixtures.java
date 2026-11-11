package com.otilm.core.util;

import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/** Connector failures as the platform's connector clients raise them. */
public final class ConnectorFailureFixtures {

    private ConnectorFailureFixtures() {
    }

    /** A problem+json refusal with {@code errorCode} and the status that code defines. */
    public static ConnectorProblemException problemRefusal(ErrorCode errorCode) {
        return problemRefusal(errorCode, errorCode.getStatus().value());
    }

    public static ConnectorProblemException problemRefusal(ErrorCode errorCode, int status) {
        ProblemDetailExtended problemDetail = new ProblemDetailExtended();
        problemDetail.setStatus(status);
        problemDetail.setErrorCode(errorCode);
        problemDetail.setDetail("connector's own words");
        return new ConnectorProblemException(problemDetail);
    }

    /** The REST client's failure for a response body over the codec's read limit. */
    public static ConnectorServerException oversizedResponse() {
        var bufferLimit = new DataBufferLimitException("Exceeded limit on max bytes to buffer : 16777216");
        var failedResponse = new WebClientResponseException(
                "200 OK from POST, but response failed with cause: " + bufferLimit, HttpStatus.OK, "OK", null, null,
                null, null);
        failedResponse.initCause(bufferLimit);
        return new ConnectorServerException("Connector response exceeded the configured read limit", failedResponse,
                HttpStatus.OK);
    }
}
