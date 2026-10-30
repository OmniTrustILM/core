package com.otilm.core.model;

import java.util.UUID;

/** Supplies a UUID-based diagnostic identity without serializing the model's contents. */
public interface IdentifiableModel {

    /**
     * Returns the object's UUID in its identity namespace.
     *
     * @return the non-null UUID of an identified object
     */
    UUID uuid();

    /**
     * Returns the UUID as diagnostic text without traversing model contents or associations.
     *
     * @return the UUID in its standard string representation
     * @throws NullPointerException if the object has not been assigned a UUID
     */
    default String toIdentifierString() {
        return uuid().toString();
    }
}
