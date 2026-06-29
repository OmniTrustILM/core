package com.otilm.core.attribute.engine;

import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.core.auth.AttributeResource;

import java.util.UUID;

/**
 * Raised when reference expansion cannot complete safely — currently only on depth-cap overflow.
 * <p>
 * Overflow is a loud failure by design (plan Q5): returning the unexpanded tail would let a bare object
 * UUID flow to the connector instead of the resolved blob, which is a silent correctness/security defect.
 * The legitimate chain is shallow (scope blob -&gt; credential, depth 2); exceeding the cap signals either a
 * mis-modelled attribute graph or a crafted cycle the visited-set somehow missed.
 */
public class ReferenceExpansionException extends RuntimeException implements PlatformException {

    public ReferenceExpansionException(String message) {
        super(message);
    }

    public static ReferenceExpansionException depthExceeded(AttributeResource kind, UUID uuid, int maxDepth) {
        return new ReferenceExpansionException(
                "Reference expansion depth cap (%d) exceeded at %s:%s".formatted(maxDepth, kind, uuid));
    }
}
