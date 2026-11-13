package com.otilm.core.service.est.message;

import com.otilm.api.exception.PlatformException;
import java.util.Optional;

/**
 * A refusal of an EST request. {@code getMessage()} is the fixed text of the {@link EstError}, so it is safe for the
 * audit record and for the wire.
 */
public final class EstException extends RuntimeException implements PlatformException {

    private final EstError error;
    private final String realm;
    private final String detail;

    public EstException(EstError error) {
        this(error, null);
    }

    /**
     * @param error what the client is told
     * @param realm the realm of the Basic challenge that an error which challenges carries; {@code null} when the
     * thrower does not name one
     */
    public EstException(EstError error, String realm) {
        this(error, realm, null);
    }

    private EstException(EstError error, String realm, String detail) {
        super(error.text());
        this.error = error;
        this.realm = realm;
        this.detail = detail;
    }

    public EstError error() {
        return error;
    }

    public Optional<String> realm() {
        return Optional.ofNullable(realm);
    }

    /**
     * Text the platform wrote, sent after the fixed sentence. It is not part of the message and is never logged, as it
     * can carry values taken from the request.
     */
    public Optional<String> detail() {
        return Optional.ofNullable(detail);
    }

    public EstException withRealm(String realm) {
        return new EstException(error, realm, detail);
    }

    public EstException withDetail(String detail) {
        return new EstException(error, realm, detail);
    }
}
