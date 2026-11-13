package com.otilm.core.service.est.message;

import org.springframework.http.HttpStatus;

/**
 * The refusals an EST client can receive: the HTTP status, the fixed sentence sent as the body, and whether the
 * response asks for HTTP Basic credentials. The sentences never carry request content, exception text or internal
 * identifiers.
 */
public enum EstError {

    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is not a base64-encoded DER PKCS#10 certification request."),
    INVALID_SIGNATURE(HttpStatus.BAD_REQUEST, "The certification request signature does not verify."),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Authentication is required.", true),
    REGISTRATION_REJECTED(HttpStatus.UNAUTHORIZED, "The request does not match an active certificate registration.",
            true),
    CERTIFICATE_REJECTED(HttpStatus.FORBIDDEN, "The client certificate is not accepted."),
    IDENTITY_MISMATCH(HttpStatus.FORBIDDEN, "The request does not match the client certificate."),
    NOT_FOUND(HttpStatus.NOT_FOUND, "Not found."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "The method is not allowed for this operation."),
    PAYLOAD_TOO_LARGE(HttpStatus.CONTENT_TOO_LARGE, "The request is too large."),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "The content type must be application/pkcs10."),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "The request could not be processed."),
    SERVICE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "The service is temporarily unavailable. Try again later."),
    REQUEST_REJECTED(HttpStatus.FORBIDDEN, "The certificate request was rejected."),
    POLICY_VIOLATION(HttpStatus.BAD_REQUEST, "The certificate request does not meet the policy of the RA profile."),
    ISSUANCE_FAILED(HttpStatus.SERVICE_UNAVAILABLE, "The certificate could not be issued. Try again later."),
    RENEWAL_NOT_ALLOWED(HttpStatus.FORBIDDEN, "Renewal with the same key is not allowed."),
    REKEY_NOT_ALLOWED(HttpStatus.FORBIDDEN, "Renewal with a new key is not allowed."),
    RENEWAL_NOT_DUE(HttpStatus.FORBIDDEN, "The certificate is not yet due for renewal."),
    SUBJECT_CHANGE_UNSUPPORTED(HttpStatus.BAD_REQUEST, "Changing the subject name is not supported."),
    RENEWAL_PENDING(HttpStatus.CONFLICT, "The certificate already has a pending renewal."),
    SERVER_KEYGEN_DISABLED(HttpStatus.FORBIDDEN, "Server-side key generation is not enabled."),
    SERVER_KEYGEN_UNAVAILABLE(HttpStatus.FORBIDDEN, "Server-side key generation is not available for this route."),
    ENCRYPTED_KEY_DELIVERY_UNSUPPORTED(HttpStatus.BAD_REQUEST, "Encrypted key delivery is not supported."),
    ISSUANCE_TIMED_OUT(HttpStatus.SERVICE_UNAVAILABLE, "The certificate could not be issued in time.");

    private final HttpStatus status;
    private final String text;
    private final boolean challenges;

    EstError(HttpStatus status, String text) {
        this(status, text, false);
    }

    EstError(HttpStatus status, String text, boolean challenges) {
        this.status = status;
        this.text = text;
        this.challenges = challenges;
    }

    public HttpStatus status() {
        return status;
    }

    public String text() {
        return text;
    }

    public boolean challenges() {
        return challenges;
    }
}
