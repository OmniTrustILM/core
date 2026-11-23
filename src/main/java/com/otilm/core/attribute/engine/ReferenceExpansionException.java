package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationException;

/**
 * Raised when references nest deeper than reference resolution follows them.
 * <p>
 * Fails loudly: sending the rest unresolved would hand the connector a bare UUID in place of content. Real chains are
 * two levels (a discovery's authority, its secret), so a deeper one is a modelling error the operator fixes on the
 * objects, and it answers as a validation refusal naming the reference.
 */
public class ReferenceExpansionException extends ValidationException {

    public ReferenceExpansionException(String message) {
        super(message);
    }

    public static ReferenceExpansionException depthExceeded(String reference, int maxDepth) {
        return new ReferenceExpansionException(
                "%s is referenced more than %d levels deep, which is more than Core resolves for a connector."
                        .formatted(reference, maxDepth));
    }
}
