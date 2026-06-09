package com.otilm.core.api;

import com.otilm.api.exception.*;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.acme.ProblemDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackages = "com.czertainly.core.api.acme")
public class AcmeExceptionHandlingAdvice {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeExceptionHandlingAdvice.class);

    /**
     * Handler for {@link AcmeProblemDocumentException}.
     *
     * @return ResponseEntity with ProblemDocument and appropriate HTTP status code
     */
    @ExceptionHandler(AcmeProblemDocumentException.class)
    public ResponseEntity<ProblemDocument> handleAcmeProblemDocumentException(AcmeProblemDocumentException ex) {
        LOG.warn("ACME Error: {}", ex.getProblemDocument());
        ResponseEntity.BodyBuilder response = ResponseEntity.status(ex.getHttpStatusCode()).contentType(MediaType.valueOf("application/problem+json"));
        if (ex.getAdditionalHeaders() != null) {
            for (String entry : ex.getAdditionalHeaders().keySet()) {
                response.header(entry, ex.getAdditionalHeaders().get(entry));
            }
        }
        return response.body(ex.getProblemDocument());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDocument> handleOtherException(Exception ex) {
        LOG.error(ex.getMessage(), ex);
        AcmeProblemDocumentException acmeException = new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        return handleAcmeProblemDocumentException(acmeException);
    }
}
