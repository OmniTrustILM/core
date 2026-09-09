package com.otilm.core.api;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.EventException;
import com.otilm.api.exception.LocationException;
import com.otilm.api.exception.NotDeletableException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.exception.ScepException;
import com.otilm.api.exception.SecretOperationException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.AuthenticationServiceExceptionDto;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.api.model.core.acme.ProblemDocument;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.exception.UnsupportedAuthorityVersionException;
import com.otilm.core.exception.UnsupportedCryptographyProviderVersionException;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.exception.AuthenticationServiceException;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BeautificationUtil;
import jakarta.validation.ConstraintViolationException;
import java.net.ConnectException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
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
        messageBuilder.append(ex.getMessage());

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
        messageBuilder.append(ex.getMessage());

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=")
                    .append(ex.getConnector().getName())
                    .append(", ")
                    .append("uuid=")
                    .append(ex.getConnector().getUuid())
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link IllegalArgumentException}. The message is logged but not returned, because this handler also
     * sees what the JDK and third-party libraries throw — an internal class name or a serializer's reference chain; a
     * rejection whose message the caller should read belongs in {@link ValidationException} instead.
     *
     * @return
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleIllegalArgumentException(IllegalArgumentException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance("The request could not be processed.");
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link MethodArgumentNotValidException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public List<String> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        // Return a string array, matching the ValidationException 422 body, so every 422 has one shape.
        List<String> errors = ex
                .getBindingResult()
                .getFieldErrors()
                .stream()
                .map(err -> err.getField() + " " + err.getDefaultMessage())
                .toList();
        LOG.info("HTTP 422: {}", errors);
        return errors;
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        LOG.debug("HTTP 422:", ex);

        return ex.getErrors().stream().map(ValidationError::getErrorDescription).toList();
    }

    /**
     * Handler for {@link ConnectorClientException}. A connector answering 401 or 403 refused the platform's (or its
     * upstream's) credentials — an upstream fault, never the caller's session — so those surface as 502; every other
     * client status stays 400.
     */
    @ExceptionHandler(ConnectorClientException.class)
    public ResponseEntity<ErrorMessageDto> handleConnectorClientException(ConnectorClientException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(ex.getMessage());

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=")
                    .append(ex.getConnector().getName())
                    .append(", ")
                    .append("uuid=")
                    .append(ex.getConnector().getUuid())
                    .append(". ");
        }

        if (ex.getHttpStatus() != null) {
            messageBuilder
                    .append(" ")
                    .append("Original response code ")
                    .append(ex.getHttpStatus().value())
                    .append(". ");
        }

        boolean authOrigin = ex.getHttpStatus() == HttpStatus.UNAUTHORIZED
                || ex.getHttpStatus() == HttpStatus.FORBIDDEN;
        HttpStatus responseStatus = authOrigin ? HttpStatus.BAD_GATEWAY : HttpStatus.BAD_REQUEST;

        if (authOrigin) {
            LOG.warn("HTTP {}: {}", responseStatus.value(), messageBuilder);
        } else {
            LOG.info("HTTP {}: {}", responseStatus.value(), messageBuilder);
        }
        return ResponseEntity.status(responseStatus).body(ErrorMessageDto.getInstance(messageBuilder.toString()));
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
        messageBuilder.append(ex.getMessage());

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=")
                    .append(ex.getConnector().getName())
                    .append(", ")
                    .append("uuid=")
                    .append(ex.getConnector().getUuid())
                    .append(". ");
        }

        if (ex.getHttpStatus() != null) {
            messageBuilder
                    .append(" ")
                    .append("Original response code ")
                    .append(ex.getHttpStatus().value())
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
        messageBuilder.append(ex.getMessage());

        if (ex.getConnector() != null) {
            messageBuilder
                    .append(" ")
                    .append("Error is related to connector ")
                    .append("name=")
                    .append(ex.getConnector().getName())
                    .append(", ")
                    .append("uuid=")
                    .append(ex.getConnector().getUuid())
                    .append(". ");
        }

        LOG.info("HTTP 503: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link ConnectorProblemException}. 401, 403, anything below 400, and anything 5xx surface as 502 — an
     * upstream fault, never the caller's session or a Core bug. Every other 4xx passes through verbatim, notably 404
     * (entity) and 422 (validation) — though for 422 only the status is preserved.
     */
    @ExceptionHandler(ConnectorProblemException.class)
    public ResponseEntity<ErrorMessageDto> handleConnectorProblemException(ConnectorProblemException ex) {
        int originalStatus = ex.getProblemDetail().getStatus();
        // Sub-400 statuses reach this handler too: the client throws for ANY non-2xx problem+json response, so a
        // connector's 3xx problem document must not surface as a bodyless-redirect-shaped Core response.
        boolean translated = HttpStatus.Series.resolve(originalStatus) != HttpStatus.Series.CLIENT_ERROR
                || originalStatus == HttpStatus.UNAUTHORIZED.value() || originalStatus == HttpStatus.FORBIDDEN.value();
        int responseStatus = translated ? HttpStatus.BAD_GATEWAY.value() : originalStatus;

        // The connector-authored problem detail is deliberately forwarded: the platform contract makes the
        // connector responsible for detail safety (bounded, no secrets), and it is the operator's diagnostic.
        StringBuilder messageBuilder = new StringBuilder(ex.getFullMessage(false));
        if (translated) {
            messageBuilder.append(" Original response code ").append(originalStatus).append(".");
        }

        if (originalStatus >= 500) {
            LOG.error("HTTP {}: {} {}", responseStatus, messageBuilder, ex.getProblemDetail());
        } else {
            LOG.warn("HTTP {}: {} {}", responseStatus, messageBuilder, ex.getProblemDetail());
        }
        return ResponseEntity.status(responseStatus).body(ErrorMessageDto.getInstance(messageBuilder.toString()));
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link AccessDeniedException}.
     *
     * @return
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthenticationServiceExceptionDto> handleAccessDeniedException(AccessDeniedException ex) {
        LOG.warn("Access denied: {}", ex.getMessage());
        ResponseEntity.BodyBuilder response = ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.valueOf("application/problem+json"));
        AuthenticationServiceExceptionDto responseDto = new AuthenticationServiceExceptionDto();
        responseDto.setCode("ACCESS_DENIED");
        responseDto.setStatusCode(HttpStatus.FORBIDDEN.value());

        String resourceName = AuthHelper.getDeniedPermissionResource();
        String resourceActionName = AuthHelper.getDeniedPermissionResourceAction();
        if (resourceName != null && !resourceName.isEmpty() && resourceActionName != null
                && !resourceActionName.isEmpty()) {
            responseDto
                    .setMessage("Access Denied. Required '" + BeautificationUtil.camelToHumanForm(resourceActionName)
                            + "' permission for '" + Resource.findByCode(resourceName).getLabel() + "'");
        } else {
            responseDto.setMessage("Access denied for the specified operation: " + ex.getMessage());
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
        ResponseEntity.BodyBuilder response = ResponseEntity
                .status(ex.getHttpStatusCode())
                .contentType(MediaType.valueOf("application/problem+json"));
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link UnsupportedAuthorityVersionException}.
     *
     * <p>
     * 400 rather than 500: an unrecognised connector interface version is caller-fixable configuration. The body is
     * fixed rather than the exception's message, which names the authority and a version string the connector reported
     * into an unvalidated column. Logged at warn -- a connector is registered that cannot be dispatched to.
     *
     * @return a fixed message that names neither the authority nor the version
     */
    @ExceptionHandler(UnsupportedAuthorityVersionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleUnsupportedAuthorityVersionException(UnsupportedAuthorityVersionException ex) {
        LOG.warn("HTTP 400: {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance("The authority's connector interface version is not supported.");
    }

    /**
     * Handler for {@link UnsupportedCryptographyProviderVersionException}.
     *
     * <p>
     * The response deliberately omits the connector-reported version while the detailed value remains available in the
     * warning log.
     *
     * @return a fixed message that names neither the token instance nor the version
     */
    @ExceptionHandler(UnsupportedCryptographyProviderVersionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleUnsupportedCryptographyProviderVersionException(
            UnsupportedCryptographyProviderVersionException ex) {
        LOG.warn("HTTP 400: {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance("The interface version of the cryptography provider is not supported.");
    }

    /**
     * Handler for {@link UnsupportedDiscoveryVersionException}.
     *
     * <p>
     * The discovery twin of {@link #handleUnsupportedAuthorityVersionException}, for the same reasons: an unrecognised
     * connector interface version is caller-fixable configuration, and the body is fixed because the exception's
     * message carries an unvalidated connector-reported version string.
     *
     * @return a fixed message that names neither the discovery nor the version
     */
    @ExceptionHandler(UnsupportedDiscoveryVersionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleUnsupportedDiscoveryVersionException(UnsupportedDiscoveryVersionException ex) {
        LOG.warn("HTTP 400: {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance("The discovery's connector interface version is not supported.");
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link AuthenticationServiceException}.
     *
     * @return
     */
    @ExceptionHandler(AuthenticationServiceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<AuthenticationServiceExceptionDto> handleCertificateOperationException(
            AuthenticationServiceException ex) {
        Integer statusCode = HttpStatus.BAD_REQUEST.value();
        if (ex.getException() != null) {
            statusCode = ex.getException().getStatusCode();
        }
        ResponseEntity.BodyBuilder response = ResponseEntity
                .status(statusCode)
                .contentType(MediaType.valueOf("application/problem+json"));
        return response.body(ex.getException());
    }

    /**
     * Handler for {@link PlatformAuthenticationException}.
     *
     * @return
     */
    @ExceptionHandler(PlatformAuthenticationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handlePlatformAuthenticationException(PlatformAuthenticationException ex) {
        LOG.info("HTTP 400: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link ScepException}.
     *
     * @return {@link ResponseEntity}
     */
    @ExceptionHandler(ScepException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleScepException(ScepException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder
                .append("SCEP error occurred: ")
                .append(ex.getMessage())
                .append(", ")
                .append("failInfo=")
                .append(ex.getFailInfo().getName());

        if (ex.getCause() != null) {
            messageBuilder.append(", ").append("cause=").append(ex.getCause().getMessage()).append(". ");
        }

        LOG.info("HTTP 400: {}", messageBuilder);
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    @ExceptionHandler(CertificateException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessageDto handleCertificateException(CertificateException ex) {
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append("Certificate error occurred: ").append(ex.getMessage());
        if (ex.getCause() != null) {
            messageBuilder.append(", ").append("cause=").append(ex.getCause().getMessage()).append(". ");
        }
        LOG.error("HTTP 500: {}", ex.getMessage());
        return ErrorMessageDto.getInstance(messageBuilder.toString());
    }

    /**
     * Handler for {@link RuleException}.
     *
     * @return
     */
    @ExceptionHandler(RuleException.class)
    public ErrorMessageDto handleRuleException(RuleException ex) {
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link EventException}.
     *
     * @return
     */
    @ExceptionHandler(EventException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleEventException(EventException ex) {
        return ErrorMessageDto.getInstance("Event `%s` error: %s".formatted(ex.getEvent().getLabel(), ex.getMessage()));
    }

    /**
     * Handler for {@link CertificateRequestException}.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(CertificateRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessageDto handleCertificateRequestException(CertificateRequestException ex) {
        // Log the cause for diagnostics, but return only our top-level message — the cause is an arbitrary
        // runtime exception whose message could leak internal detail to the API consumer.
        LOG.info("HTTP 400 (CertificateRequestException): {}", ex.getMessage(), ex);
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
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
        return ErrorMessageDto.getInstance(ex.getMessage());
    }

    /**
     * Handler for {@link DataIntegrityViolationException}.
     *
     * <p>
     * The response is deliberately identical to {@link #handleException(Exception)} -- same status, same body. What
     * differs is the log line. A database integrity failure carries the server's {@code DETAIL} text, which quotes the
     * failing row: {@code Key (identity_key)=(...) already exists}, or {@code Failing row contains (...)}. Logging the
     * message and the cause chain therefore writes row data into the application log, and for {@code crypto_asset} that
     * row data is the identity key, whose whole protection is that it never leaves the database. A log line is the same
     * disclosure as a response field, and logs travel further.
     *
     * <p>
     * So ERROR carries only what identifies the failure without quoting the data: the exception classes, the SQL state,
     * and the violated constraint's name -- which is the actionable datum in nearly every case. The full throwable
     * stays available at DEBUG for an operator who has decided they need it.
     *
     * @return {@link ErrorMessageDto}
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessageDto handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        LOG
                .error("Database integrity violation: {} ({}), constraint {}", ex.getClass().getName(),
                        sqlStateOf(ex).orElse("no SQL state"),
                        CryptoAssetConstraintTranslator.constraintNameOf(ex).orElse("unnamed"));
        LOG.debug("Database integrity violation detail", ex);
        return ErrorMessageDto.getInstance("Internal server error.");
    }

    /**
     * The driver's SQL state, which classifies the failure without quoting any row. Read from the cause chain rather
     * than from the message, for the same reason the constraint name is.
     */
    private static Optional<String> sqlStateOf(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sqlFailure && sqlFailure.getSQLState() != null) {
                return Optional.of(sqlFailure.getSQLState());
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return Optional.empty();
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
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorMessageDto(ex.getMessage()));
        }
        String message = StringUtils.isNotBlank(ex.getProblemDetail().getDetail())
                ? ex.getProblemDetail().getDetail()
                : ex.getMessage();
        return ResponseEntity.status(ex.getProblemDetail().getStatus()).body(new ErrorMessageDto(message));
    }
}
