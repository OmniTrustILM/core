package com.otilm.core.service.acme.eab;

import com.otilm.api.exception.PlatformException;

/**
 * The secret registered on the ACME profile does not hold usable HS256 key material — a content type that carries no
 * key, a value that is not base64url, or fewer bytes than HS256 requires. A configuration fault of the profile rather
 * than a wrong credential, so it is reported to the client as an internal error and never as a rejected binding.
 *
 * <p>
 * The reason it carries names the shape of the configured secret and is written here rather than derived from a cause,
 * so it is safe for {@link PlatformException#safeMessage} to expose. The ACME layer still replaces it with a generic
 * problem detail, since which of a profile's keys is misconfigured is not the client's to learn.
 */
public class UnusableEabKeyException extends RuntimeException implements PlatformException {

    public UnusableEabKeyException(String reason) {
        super(reason);
    }

    public UnusableEabKeyException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
