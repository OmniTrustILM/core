package com.otilm.core.signing.engine.error;

import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.HttpStatus;
import org.springframework.util.unit.DataSize;

import static java.util.Map.entry;

/**
 * Classifies a connector's failure by its {@code errorCode}. One refusal is then reported alike at every call site and
 * over every transport.
 */
public final class ConnectorRefusalClassifier {

    private static final Map<ErrorCode, SigningEngineFailure> FAILURE_BY_CODE = Map
            .ofEntries(entry(ErrorCode.DOCUMENT_MALFORMED, SigningEngineFailure.MALFORMED_INPUT),
                    entry(ErrorCode.DOCUMENT_TOO_LARGE, SigningEngineFailure.INVALID_INPUT),
                    entry(ErrorCode.SIGNATURE_NOT_FOUND, SigningEngineFailure.INVALID_INPUT),
                    entry(ErrorCode.SIGNATURE_PLACEMENT_REJECTED, SigningEngineFailure.INVALID_INPUT),
                    entry(ErrorCode.DOCUMENT_SIGNING_FORBIDDEN, SigningEngineFailure.INVALID_INPUT),
                    entry(ErrorCode.PARAMETER_UNSUPPORTED, SigningEngineFailure.MISCONFIGURED));

    /** Refusals blaming Core's request body. The fault lies between Core and the connector. */
    private static final Set<ErrorCode> CONTRACT_BREACHES = EnumSet
            .of(ErrorCode.VALIDATION_FAILED, ErrorCode.CONTEXT_MISMATCH);

    private static final Classification UNSUPPORTED_CONFIGURATION = new Classification(
            SigningEngineFailure.MISCONFIGURED, "Signing configuration is not supported.");

    private ConnectorRefusalClassifier() {
    }

    /** A failure class with the wire-safe text a caller reads for it. */
    public record Classification(SigningEngineFailure failure, String clientMessage) {
    }

    /**
     * The classification {@code connectorFailure} carries, defaulting to {@code unclassified}. A refusal without a code
     * counts as a misconfiguration.
     */
    public static Classification classify(Exception connectorFailure, Classification unclassified) {
        if (connectorFailure instanceof ConnectorProblemException problem) {
            return classifyProblem(problem.getProblemDetail(), unclassified);
        }
        if (isRefusalWithoutCode(connectorFailure)) {
            return UNSUPPORTED_CONFIGURATION;
        }
        return unclassified;
    }

    /**
     * Classifies the failure of a call sized by the caller's document. A response over {@code readLimit} counts as an
     * oversized document from the caller.
     */
    public static Classification classifyDocumentCall(Exception connectorFailure, DataSize readLimit,
            Classification unclassified) {
        if (ExceptionUtils.indexOfType(connectorFailure, DataBufferLimitException.class) >= 0) {
            return new Classification(SigningEngineFailure.INVALID_INPUT,
                    "Document is too large for the %s response limit".formatted(inLargestWholeUnit(readLimit)));
        }
        return classify(connectorFailure, unclassified);
    }

    /** The status is read as a number. A connector may answer with a status outside {@link HttpStatus}. */
    private static Classification classifyProblem(ProblemDetailExtended problem, Classification unclassified) {
        ErrorCode errorCode = problem.getErrorCode();
        if (errorCode == null) {
            return problem.getStatus() == HttpStatus.UNPROCESSABLE_CONTENT.value()
                    ? UNSUPPORTED_CONFIGURATION
                    : unclassified;
        }
        if (CONTRACT_BREACHES.contains(errorCode)) {
            return new Classification(SigningEngineFailure.CONNECTOR_FAULT, unclassified.clientMessage());
        }
        SigningEngineFailure failure = FAILURE_BY_CODE.get(errorCode);
        return failure == null ? unclassified : new Classification(failure, errorCode.getTitle());
    }

    /** A connector's 422 without a problem document, or a platform check failing ahead of the connector call. */
    private static boolean isRefusalWithoutCode(Exception connectorFailure) {
        return connectorFailure instanceof ValidationException || isEmptyRefusal(connectorFailure);
    }

    /** A problem+json 422 with an empty body. The REST client raises it as a plain {@link ConnectorClientException}. */
    private static boolean isEmptyRefusal(Exception connectorFailure) {
        return connectorFailure instanceof ConnectorClientException clientError
                && clientError.getHttpStatus() == HttpStatus.UNPROCESSABLE_CONTENT;
    }

    /** A readable size for the client message, such as {@code 16MB}. */
    private static String inLargestWholeUnit(DataSize size) {
        long bytes = size.toBytes();
        if (bytes % DataSize.ofMegabytes(1).toBytes() == 0) {
            return size.toMegabytes() + "MB";
        }
        if (bytes % DataSize.ofKilobytes(1).toBytes() == 0) {
            return size.toKilobytes() + "KB";
        }
        return bytes + "B";
    }
}
