package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationException;

/**
 * Raised when references nest deeper than reference resolution follows them.
 * <p>
 * Overflow is a loud failure by design: sending the rest unresolved would let a bare object UUID reach the connector in
 * place of the object's content. The chains connectors use are shallow (a discovery's authority and the authority's
 * secret are two levels), so exceeding the cap means the attribute graph is modelled wrongly. The operator fixes that
 * on the objects, so it answers as a validation refusal naming the reference.
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
