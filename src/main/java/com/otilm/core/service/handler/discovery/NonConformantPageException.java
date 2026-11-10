package com.otilm.core.service.handler.discovery;

/**
 * A drained page missing a field the contract requires for the run's delivery mode, such as the checkpoint every page
 * of a checkpointed run carries. Thrown inside the page's transaction, so nothing of the page is kept.
 */
public class NonConformantPageException extends RuntimeException {

    public NonConformantPageException(String message) {
        super(message);
    }
}
