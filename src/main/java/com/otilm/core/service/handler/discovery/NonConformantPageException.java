package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.PlatformException;

/**
 * A drained page missing a field the contract requires for the run's delivery mode, such as the checkpoint every page
 * of a checkpointed run carries. Thrown inside the page's transaction, so nothing of the page is kept. Its message is
 * Core's own.
 */
public class NonConformantPageException extends RuntimeException implements PlatformException {

    public NonConformantPageException(String message) {
        super(message);
    }
}
