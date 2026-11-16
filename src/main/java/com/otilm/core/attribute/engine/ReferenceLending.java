package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import java.util.UUID;

/**
 * Decides who resolves the references inside an object a request refers to. Core lends an object's own references only
 * to the connector the object belongs to: the authority a discovery names gives that discovery's connector its OAuth
 * client secret and TLS trust, which the same connector already receives for every operation of the authority.
 */
@FunctionalInterface
public interface ReferenceLending {

    /** Lends nothing: the references inside a referenced object stay references. */
    ReferenceLending NOTHING = (kind, uuid) -> null;

    /**
     * @return the loader for the references inside the object, or {@code null} to leave them as references
     */
    ReferenceLoader insideOf(AttributeResource kind, UUID uuid);
}
