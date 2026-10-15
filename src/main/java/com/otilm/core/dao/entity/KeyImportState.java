package com.otilm.core.dao.entity;

/**
 * How far an import attempt got. {@code REQUESTED} is recorded before the connector is asked, and {@code ACCEPTED} once
 * the connector took the import on asynchronously; while in either, the connector may hold a key the platform has not
 * registered. {@code COMPENSATING} is taken by the reconciliation before it destroys a key the requester never
 * received. {@code COMPLETED} ends in a registered key, {@code FAILED} in nothing imported, {@code COMPENSATED} in a
 * destroyed key, {@code QUARANTINED} in a key the connector would not destroy, registered deactivated, and
 * {@code UNRESOLVED} in an outcome that could not be learned in time.
 */
public enum KeyImportState {
    REQUESTED,
    ACCEPTED,
    COMPENSATING,
    COMPLETED,
    FAILED,
    COMPENSATED,
    QUARANTINED,
    UNRESOLVED;

    /** Whether the outcome is still to be learned. */
    public boolean isOpen() {
        return this == REQUESTED || this == ACCEPTED;
    }

    /** Whether the reconciliation still has to settle the attempt. */
    public boolean isUnsettled() {
        return isOpen() || this == COMPENSATING;
    }
}
