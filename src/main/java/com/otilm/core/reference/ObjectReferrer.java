package com.otilm.core.reference;

import java.util.List;

/**
 * An object that would break if the object it references were deleted. A refusal names it only to a caller who may see
 * every object in {@code disclosedObjects}, since its role can name another object too.
 */
public record ObjectReferrer(ObjectRef object, String name, String role, List<ObjectRef> disclosedObjects) {

    public ObjectReferrer {
        disclosedObjects = List.copyOf(disclosedObjects);
    }

    public ObjectReferrer(ObjectRef object, String name, String role) {
        this(object, name, role, List.of(object));
    }

    String describe() {
        return "%s '%s' (%s)".formatted(object.resource().getLabel(), name, role);
    }
}
