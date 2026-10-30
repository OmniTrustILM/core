package com.otilm.core.events.handlers.discovery;

import com.otilm.api.exception.PlatformException;

/**
 * Carries an already-shaped, exposure-safe reason out of a group import that has to roll back.
 *
 * <p>
 * Throwing is what rolls the transaction back, so the reason has to survive the throw. Without a type
 * {@link DiscoveryFailureReason} recognises, the caller's own shaping would see an unclassified wrapper and replace the
 * reason it carries with generic text.
 *
 * <p>
 * This is the only type whose message {@link DiscoveryFailureReason} forwards to {@code processedError}. Every message
 * reaching an instance of it has been through that shaping already, which is what makes forwarding safe —
 * {@link PlatformException} alone is not enough of a guarantee, since it marks a message the platform authored rather
 * than one free of entity data.
 */
public class DiscoveryImportRollbackException extends RuntimeException implements PlatformException {

    public DiscoveryImportRollbackException(String shapedReason, Throwable cause) {
        super(shapedReason, cause);
    }
}
