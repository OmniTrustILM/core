package com.otilm.core.service.v2;

/** What the connector confirmed about a pending certificate operation that the platform cancelled locally. */
public enum CancelConfirmation {
    /** The connector cancelled the operation. */
    CANCELLED,
    /** The connector does not know the operation. */
    NOT_TRACKED,
    /** The connector could not be asked or did not answer, so the operation may still complete upstream. */
    UNCONFIRMED
}
