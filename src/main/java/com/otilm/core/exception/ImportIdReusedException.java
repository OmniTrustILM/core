package com.otilm.core.exception;

import com.otilm.api.exception.PlatformException;

/**
 * An import identifier its requester used before to import something else, answered with a conflict. It is unchecked
 * because the method of the certificate import contract declares no conflict.
 */
public class ImportIdReusedException extends RuntimeException implements PlatformException {

    public ImportIdReusedException(String message) {
        super(message);
    }
}
