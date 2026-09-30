package com.otilm.core.model.crypto;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.core.dao.entity.KeyImport;
import java.util.UUID;

/**
 * An import attempt the reconciliation claimed, with what it needs to settle it.
 *
 * @param attempt the attempt as it was claimed
 * @param tokenProfileUuid the token profile the key was to be imported into
 * @param tokenInstanceUuid the token instance of the token profile
 * @param name the name the key was to be registered under
 * @param requester the user who imported the key
 * @param exportable whether the private key may later be exported
 * @param lastLook whether this is the attempt's last look, since it was last sent longer ago than the connector is
 * trusted to keep its records: what the look cannot settle ends unresolved
 */
public record KeyImportCheck(KeyImportAttempt attempt, UUID tokenProfileUuid, UUID tokenInstanceUuid, String name,
        NameAndUuidDto requester, boolean exportable, boolean lastLook) {

    public static KeyImportCheck of(KeyImport attempt, boolean lastLook) {
        return new KeyImportCheck(KeyImportAttempt.of(attempt), attempt.getTokenProfileUuid(),
                attempt.getTokenInstanceUuid(), attempt.getName(),
                new NameAndUuidDto(attempt.getRequesterUuid().toString(), attempt.getRequesterName()),
                attempt.isExportable(), lastLook);
    }
}
