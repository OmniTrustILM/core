package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationException;

/**
 * A request refers to an object that belongs to another connector than the one the request goes to. Refused before the
 * object is loaded, as a validation refusal naming the attribute and the object.
 */
public class ForeignReferenceException extends ValidationException {

    /**
     * @param holder the attribute holding the reference, as {@code Attribute '<name>'}, with its object when nested
     * @param reference the object, as {@code <kind> '<name>'}
     */
    public ForeignReferenceException(String holder, String reference) {
        super("%s refers to %s, which belongs to another connector. Select another one.".formatted(holder, reference));
    }
}
