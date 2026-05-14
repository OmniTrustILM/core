package com.czertainly.core.security.exception;

import com.czertainly.api.exception.PlatformException;
import com.czertainly.api.model.common.AuthenticationServiceExceptionDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;

public class AuthenticationServiceException extends AuthenticationException implements PlatformException {

    @Schema(description = "Exception Information", required = true)
    private AuthenticationServiceExceptionDto exception;


    public AuthenticationServiceException(String message) {
        super(message);
        System.out.println(message);
    }

    public AuthenticationServiceException(String message, Boolean isException) {
        super("Authorization Exception");
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        try {
            this.exception = mapper.readValue(message, AuthenticationServiceExceptionDto.class);
        } catch (JsonProcessingException e) {
            this.exception = new AuthenticationServiceExceptionDto(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed parsing error from Authentication Service");
        }
    }

    public AuthenticationServiceException(AuthenticationServiceExceptionDto exception) {
        super("Authentication Service Exception");
        this.exception = exception;
    }

    public AuthenticationServiceException(Integer statusCode, String message) {
        super("Authentication Service Exception");
        AuthenticationServiceExceptionDto dto = new AuthenticationServiceExceptionDto();
        dto.setMessage(message);
        dto.setStatusCode(statusCode);
    }

    public AuthenticationServiceExceptionDto getException() {
        return exception;
    }

    public void setException(AuthenticationServiceExceptionDto exception) {
        this.exception = exception;
    }
}

