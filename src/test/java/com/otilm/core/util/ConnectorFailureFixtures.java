package com.otilm.core.util;

import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import java.io.IOException;
import java.net.URI;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Connector failures as the platform's connector clients raise them. The decode and request failures carry the text
 * they are given, which stands for the text of the answer, so a test can show that a log does not repeat it.
 */
public final class ConnectorFailureFixtures {

    private static final URI CONNECTOR_URI = URI.create("http://connector.test/attributes");

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

    /** What the client raises for an answer with a good status whose content it cannot decode. */
    public static WebClientResponseException decodeFailure(String answerText) {
        WebClientResponseException failure = new WebClientResponseException(
                "200 OK from POST " + CONNECTOR_URI + ", but response failed with cause: " + answerText,
                HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase(), HttpHeaders.EMPTY, null, null);
        failure.initCause(new IllegalStateException(answerText));
        return failure;
    }

    /** What the client raises for a request that does not get an answer. */
    public static WebClientRequestException requestFailure(String text) {
        return new WebClientRequestException(new IOException(text), HttpMethod.POST, CONNECTOR_URI, HttpHeaders.EMPTY);
    }
}
