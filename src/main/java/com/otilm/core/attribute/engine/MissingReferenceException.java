package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationException;

/**
 * A stored reference whose object is gone, as a validation refusal naming the attribute that holds it. Raised where a
 * resolution can only declare unchecked failures.
 */
public class MissingReferenceException extends ValidationException {

    public MissingReferenceException(String message) {
        super(message);
    }
}
