package com.otilm.core.attribute.engine;

import com.otilm.api.exception.PlatformException;
import org.springframework.security.access.AccessDeniedException;

/**
 * A refusal to resolve a reference, naming the object it refers to. The authorization check names only the permission
 * it missed, which leaves the caller guessing which of the objects a request reaches it was about.
 */
public class ReferenceAccessDeniedException extends AccessDeniedException implements PlatformException {

    private final String reference;

    public ReferenceAccessDeniedException(String reference, AccessDeniedException cause) {
        super("Access denied to %s: %s".formatted(reference, cause.getMessage()), cause);
        this.reference = reference;
    }

    /** The object refused, as {@code <kind> '<name>'}, with the attribute and object holding it when nested. */
    public String getReference() {
        return reference;
    }
}
