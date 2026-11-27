package com.otilm.core.service.trust;

import com.otilm.api.exception.ValidationException;

/**
 * A request to change platform trust where ILM does not manage it.
 */
public class PlatformTrustNotManagedException extends ValidationException {

    public PlatformTrustNotManagedException(String message) {
        super(message);
    }
}
