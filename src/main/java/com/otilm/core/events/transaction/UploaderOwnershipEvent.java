package com.otilm.core.events.transaction;

import java.util.UUID;

/**
 * Asks for the user who uploaded a certificate to be made its owner once the upload has committed.
 */
public record UploaderOwnershipEvent(UUID certificateUuid, UUID uploaderUuid, String uploaderName) {
}
