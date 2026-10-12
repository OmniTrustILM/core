package com.otilm.core.reference;

import java.util.List;

/**
 * An object that breaks when the object it references is deleted. A refusal names it only to a caller allowed to see
 * all of {@code disclosedObjects}: the referrer and whatever its role mentions.
 */
public record ObjectReferrer(ObjectRef object, String name, String role, List<ObjectRef> disclosedObjects) {

    public ObjectReferrer(ObjectRef object, String name, String role) {
        this(object, name, role, List.of(object));
    }

    String describe() {
        return "%s '%s' (%s)".formatted(object.resource().getLabel(), name, role);
    }
}
