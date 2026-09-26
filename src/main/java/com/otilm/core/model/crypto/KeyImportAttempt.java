package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * One import attempt as it was read.
 *
 * @param uuid the attempt, which is also the import identifier the connector knows it by
 * @param keyReference the reference the connector binds the key to
 * @param state how far the attempt got
 * @param operationMeta the connector's handle for an import it runs asynchronously, or {@code null}
 * @param createdAt when the attempt was recorded
 * @param secretDigests the digests of the secrets the attempt was sent with, which no answer about it may carry back
 */
public record KeyImportAttempt(UUID uuid, UUID keyReference, KeyImportState state,
        List<MetadataAttribute> operationMeta, OffsetDateTime createdAt, List<String> secretDigests) {

    public static KeyImportAttempt of(KeyImport attempt) {
        return new KeyImportAttempt(attempt.getUuid(), attempt.getKeyReference(), attempt.getState(),
                attempt.getOperationMeta(), attempt.getCreatedAt(), attempt.getSecretDigests());
    }
}
