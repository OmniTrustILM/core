package com.otilm.core.api;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.common.ErrorMessageDto;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExceptionHandlingAdviceTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    @Test
    void handleCbomRepositoryException_ShouldUseProblemDetailDetailWhenPresent() {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "version must be an integer");
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("version must be an integer", response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldFallbackToExceptionMessageWhenDetailIsBlank() {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setDetail("");
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ex.getMessage(), response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldFallbackToExceptionMessageWhenDetailIsNull() {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setDetail(null);
        CbomRepositoryException ex = new CbomRepositoryException(problemDetail);

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(ex.getMessage(), response.getBody().getMessage());
    }

    @Test
    void handleCbomRepositoryException_ShouldReturnInternalServerErrorWhenProblemDetailIsNull() {
        CbomRepositoryException ex = new CbomRepositoryException("Upload of BOM failed.");

        ResponseEntity<ErrorMessageDto> response = advice.handleCbomRepositoryException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Upload of BOM failed.", response.getBody().getMessage());
    }
}
