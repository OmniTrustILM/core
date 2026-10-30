package com.otilm.core.model;

import com.otilm.core.util.IdentifierStringUtils;

/** Adds an optional display name to an object's UUID-based diagnostic identity. */
public interface NamedModel extends IdentifiableModel {

    /**
     * Returns the object's display name.
     *
     * @return the name, which may be null or blank
     */
    String name();

    /**
     * Formats the identity as {@code name (uuid)}, escaping line breaks in the name. A null or blank name falls back to
     * the UUID alone. The display name is diagnostic context; the UUID remains the object's identity.
     *
     * @return the name and UUID, or the UUID alone when no name is available
     */
    @Override
    default String toIdentifierString() {
        String name = name();
        boolean missingName = name == null || name.isBlank();
        if (missingName) {
            return IdentifiableModel.super.toIdentifierString();
        }
        String escapedName = IdentifierStringUtils.escapeLineBreaks(name);
        return escapedName + " (" + uuid() + ")";
    }
}
