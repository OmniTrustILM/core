package com.czertainly.core.api;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.common.AuthenticationServiceExceptionDto;
import com.czertainly.api.model.common.ErrorMessageDto;
import com.czertainly.api.model.core.acme.ProblemDocument;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.exception.AuthenticationServiceException;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.BeautificationUtil;
import jakarta.validation.ConstraintViolationException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestValueException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.net.ConnectException;
import java.security.cert.CertificateException;
import java.util.List;

@RestControllerAdvice
public class ExceptionHandlingAdvice {

    private static final Logger LOG = LoggerFactory.getLogger(ExceptionHandlingAdvice.class);

    /**
     * Handler for {@link NotFoundException}.
     *
     * @param ex Caught {@link NotFoundException}.
     * @return
     */
    @ExceptionHandler(NotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorMessageDto handleNotFoundException(NotFoundException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(PlatformException.safeMessage(ex, "Resource not found"));

        LOG.warn("HTTP 404: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConnectorEntityNotFoundException}.
     *
     * @param ex Caught {@link ConnectorEntityNotFoundException}.
     * @return
     */
    @ExceptionHandler(ConnectorEntityNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorMessageDto handleConnectorEntityNotFoundException(ConnectorEntityNotFoundException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(PlatformException.safeMessage(ex, "Connector entity not found"));

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=").append(ex.getConnector().getName()).append(", ")
                    .append("uuid=").append(ex.getConnector().getUuid())
                    .append(". ");
        }

        LOG.warn("HTTP 404: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link NoHandlerFoundException}.
     *
     * @param ex Caught {@link NoHandlerFoundException}.
     * @return
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorMessageDto handleNoHandlerFoundException(NoHandlerFoundException ex) {
        LOG.info("HTTP 404: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Requested endpoint not found");
    }

    /**
     * Handler for {@link AlreadyExistException}.
     *
     * @return
     */
    @ExceptionHandler(AlreadyExistException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorMessageDto handleAlreadyExistException(AlreadyExistException ex) {
        LOG.info("HTTP 409: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Resource already exists"));
    }

    /**
     * Handler for {@link org.springframework.web.HttpRequestMethodNotSupportedException}.
     *
     * @return
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("HTTP method not supported");
    }

    /**
     * Handler for {@link IllegalArgumentException}.
     *
     * @return
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleIllegalArgumentException(IllegalArgumentException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Invalid argument");
    }

    /**
     * Handler for {@link MethodArgumentTypeMismatchException}.
     *
     * @return
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleMethodArgumentTypeMismatchException(MethodArgumentTypeMismatchException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Invalid argument type");
    }

    /**
     * Handler for {@link MethodArgumentNotValidException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public ErrorMessageDto handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append("Validation error: ");
        ex.getBindingResult().getFieldErrors().forEach(
                err -> messageBuilder.append(err.getField()).append(" ").append(err.getDefaultMessage()).append(", ")
        );
        // remote trailing comma and space
        messageBuilder.delete(messageBuilder.length() - 2, messageBuilder.length());

        LOG.info("HTTP 422: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConstraintViolationException}.
     *
     * @return
     */
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleConstraintViolationException(ConstraintViolationException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append("Validation error: ");
        ex.getConstraintViolations().forEach(err -> messageBuilder.append(err.getMessage()).append(", "));
        // remote trailing comma and space
        messageBuilder.delete(messageBuilder.length() - 2, messageBuilder.length());

        LOG.info("HTTP 400: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link MissingRequestValueException}.
     *
     * @return
     */
    @ExceptionHandler(MissingRequestValueException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleMissingRequestValueException(MissingRequestValueException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Required request value is missing");
    }

    /**
     * Handler for {@link NotDeletableException}.
     *
     * @return
     */
    @ExceptionHandler(NotDeletableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleNotDeletableException(NotDeletableException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Object cannot be deleted"));
    }

    /**
     * Handler for {@link ValidationException}.
     *
     * @return
     */
    @ExceptionHandler(ValidationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public List<String> handleValidationException(ValidationException ex) {
        LOG.info("HTTP 422: {}", ex.getMessage());

        return ex.getErrors().stream()
                .map(ValidationError::getErrorDescription)
                .toList();
    }

    /**
     * Handler for {@link ConnectorClientException}.
     *
     * @return
     */
    @ExceptionHandler(ConnectorClientException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleConnectorClientException(ConnectorClientException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(PlatformException.safeMessage(ex, "Connector client error"));

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=").append(ex.getConnector().getName()).append(", ")
                    .append("uuid=").append(ex.getConnector().getUuid())
                    .append(". ");
        }

        if (ex.getHttpStatus() != null) {
            messageBuilder
                    .append(" ")
                    .append("Original response code ")
                    .append(ex.getHttpStatus())
                    .append(". ");
        }

        LOG.info("HTTP 400: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConnectorServerException}.
     *
     * @return
     */
    @ExceptionHandler(ConnectorServerException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public ErrorMessageDto handleConnectorServerException(ConnectorServerException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(PlatformException.safeMessage(ex, "Connector server error"));

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=").append(ex.getConnector().getName()).append(", ")
                    .append("uuid=").append(ex.getConnector().getUuid())
                    .append(". ");
        }

        if (ex.getHttpStatus() != null) {
            messageBuilder
                    .append(" ")
                    .append("Original response code ")
                    .append(ex.getHttpStatus())
                    .append(". ");
        }

        LOG.info("HTTP 502: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConnectorCommunicationException}.
     *
     * @return
     */
    @ExceptionHandler(ConnectorCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorMessageDto handleConnectorCommunicationException(ConnectorCommunicationException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(PlatformException.safeMessage(ex, "Connector communication error"));

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=").append(ex.getConnector().getName()).append(", ")
                    .append("uuid=").append(ex.getConnector().getUuid())
                    .append(". ");
        }

        LOG.info("HTTP 503: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConnectorProblemException}.
     *
     * @return ResponseEntity with status code from the exception and body containing error message.
     */
    @ExceptionHandler(ConnectorProblemException.class)
    public ResponseEntity<ErrorMessageDto> handleConnectorProblemException(ConnectorProblemException ex) {
        String errorMessage = ex.getFullMessage(false);
        if (LOG.isErrorEnabled()) {
            LOG.error("HTTP %d: %s %s".formatted(ex.getHttpStatus().value(), errorMessage, ex.getProblemDetail().toString()));
        }

        ErrorMessageDto errorMessageDto = ErrorMessageDto.getInstance(errorMessage);
        return ResponseEntity.status(ex.getProblemDetail().getStatus()).body(errorMessageDto);
    }

    /**
     * Handler for {@link HttpMessageNotReadableException}.
     *
     * @return
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleMessageNotReadable(HttpMessageNotReadableException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Unable to read HTTP message");
    }

    /**
     * Handler for {@link java.net.ConnectException}.
     *
     * @return
     */
    @ExceptionHandler(ConnectException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleConnectException(ConnectException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("Connection to external service failed");
    }

    /**
     * Handler for {@link AttributeException}.
     *
     * @return
     */
    @ExceptionHandler(AttributeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleAttributeException(AttributeException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Attribute error"));
    }

    /**
     * Handler for {@link AccessDeniedException}.
     *
     * @return
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthenticationServiceExceptionDto> handleAccessDeniedException(AccessDeniedException ex) {
        LOG.warn("Access denied: {}", ex.getMessage());
        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.FORBIDDEN).contentType(MediaType.valueOf("application/problem+json"));
        AuthenticationServiceExceptionDto responseDto = new AuthenticationServiceExceptionDto();
        responseDto.setCode("ACCESS_DENIED");
        responseDto.setStatusCode(HttpStatus.FORBIDDEN.value());

        String resourceName = AuthHelper.getDeniedPermissionResource();
        String resourceActionName = AuthHelper.getDeniedPermissionResourceAction();
        if (resourceName != null && !resourceName.isEmpty() && resourceActionName != null && !resourceActionName.isEmpty()) {
            responseDto.setMessage("Access Denied. Required '"
                    + BeautificationUtil.camelToHumanForm(resourceActionName)
                    + "' permission for '"
                    + Resource.findByCode(resourceName).getLabel()
                    + "'");
        } else {
            responseDto.setMessage("Access denied");
        }
        return response.body(responseDto);
    }

    /**
     * Handler for {@link AcmeProblemDocumentException}.
     *
     * @return
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

    /**
     * Handler for {@link LocationException}.
     *
     * @return
     */
    @ExceptionHandler(LocationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleLocationException(LocationException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Location error"));
    }

    /**
     * Handler for {@link CertificateOperationException}.
     *
     * @return
     */
    @ExceptionHandler(CertificateOperationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleCertificateOperationException(CertificateOperationException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Certificate operation error"));
    }

    /**
     * Handler for {@link SecretOperationException}.
     *
     * @return
     */
    @ExceptionHandler(SecretOperationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleSecretOperationException(SecretOperationException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Secret operation error"));
    }


    /**
     * Handler for {@link AuthenticationServiceException}.
     *
     * @return
     */
    @ExceptionHandler(AuthenticationServiceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<AuthenticationServiceExceptionDto> handleCertificateOperationException(AuthenticationServiceException ex) {
        Integer statusCode = HttpStatus.BAD_REQUEST.value();
        if (ex.getException() != null) {
            statusCode = ex.getException().getStatusCode();
        }
        ResponseEntity.BodyBuilder response = ResponseEntity.status(statusCode).contentType(MediaType.valueOf("application/problem+json"));
        return response.body(ex.getException());
    }

    /**
     * Handler for {@link CzertainlyAuthenticationException}.
     *
     * @return
     */
    @ExceptionHandler(CzertainlyAuthenticationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleCzertainlyAuthenticationException(CzertainlyAuthenticationException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Authentication error"));
    }

    /**
     * Handler for {@link ScepException}.
     *
     * @return {@link ResponseEntity}
     */
    @ExceptionHandler(ScepException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleScepException(ScepException ex) {
        String scepMessage = PlatformException.safeMessage(ex, "SCEP error");
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append("SCEP error occurred: ")
                .append(scepMessage)
                .append(", ")
                .append("failInfo=").append(ex.getFailInfo().getName());

        LOG.info("HTTP 400: {}", messageBuilder, ex);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    @ExceptionHandler(CertificateException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessageDto handleCertificateException(CertificateException ex) {
        LOG.error("HTTP 500: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Certificate error"));
    }

    /**
     * Handler for {@link RuleException}.
     *
     * @return
     */
    @ExceptionHandler(RuleException.class)
    public ErrorMessageDto handleRuleException(RuleException ex) {
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Rule evaluation error"));
    }

    /**
     * Handler for {@link EventException}.
     *
     * @return
     */
    @ExceptionHandler(EventException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleEventException(EventException ex) {
        return ErrorMessageDto.getInstance("Event `%s` error: %s".formatted(
                ex.getEvent().getLabel(),
                PlatformException.safeMessage(ex, "Event processing failed")));
    }

    /**
     * Handler for {@link CertificateRequestException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(CertificateRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleCertificateRequestException(CertificateRequestException ex) {
        LOG.error("HTTP 400 (CertificateRequestException): {}, {}", ex.getMessage(), ex.getCause().getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Certificate request error"));
    }

    /**
     * Handler for {@link NotSupportedException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(NotSupportedException.class)
    @ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
    public ErrorMessageDto handleTokenInstanceException(NotSupportedException ex) {
        LOG.debug("HTTP 501: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(PlatformException.safeMessage(ex, "Token instance exception"));
    }

    /**
     * Handler for {@link WebClientRequestException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(WebClientRequestException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessageDto handleWebClientRequestException(WebClientRequestException ex) {
        LOG.error("WebClient request error occurred: {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance("External service request failed");
    }

    /**
     * Handler for {@link Exception}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessageDto handleException(Exception ex) {
        LOG.error("General error occurred: {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance("Internal server error.");
    }

    /**
     * Handler for {@link CbomRepositoryException}
     *
     * @return {@link ResponseEntity}
     */
    @ExceptionHandler(CbomRepositoryException.class)
    public ResponseEntity<ErrorMessageDto> handleCbomRepositoryException(CbomRepositoryException ex) {
        LOG.error("CBOM repository error occurred: {}. Detail: {}", ex.getMessage(), ex.getProblemDetail());
        if (ex.getProblemDetail() == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorMessageDto(PlatformException.safeMessage(ex, "CBOM repository error")));
        }
        String message = StringUtils.isNotBlank(ex.getProblemDetail().getDetail())
                ? ex.getProblemDetail().getDetail()
                : PlatformException.safeMessage(ex, "CBOM repository error");
        return ResponseEntity.status(ex.getProblemDetail().getStatus()).body(new ErrorMessageDto(message));
    }
}
