package com.otilm.core.dao.entity;

/**
 * How far an import attempt got. {@code REQUESTED} is recorded before the connector is asked, and {@code ACCEPTED} once
 * the connector took the import on asynchronously; while in either, the connector may hold a key the platform has not
 * registered. {@code COMPLETED} ends in a registered key, {@code FAILED} in nothing imported.
 */
public enum KeyImportState {
    REQUESTED,
    ACCEPTED,
    COMPLETED,
    FAILED;

    /** Whether the outcome is still to be learned. */
    public boolean isOpen() {
        return this == REQUESTED || this == ACCEPTED;
    }
}
