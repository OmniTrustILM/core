package com.otilm.core.exception;

import com.otilm.api.exception.NotFoundException;

/**
 * A stored attribute reference whose object is gone. It stays a checked {@link NotFoundException}, so a transaction it
 * crosses can still commit, as a secret action putting back its state must; the API answers it with 422.
 */
public class DanglingReferenceException extends NotFoundException {
    public DanglingReferenceException(String message) {
        super(message);
    }
}
