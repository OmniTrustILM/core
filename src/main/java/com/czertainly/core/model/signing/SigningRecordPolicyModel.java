package com.czertainly.core.model.signing;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;

/**
 * Model layer representation of a Signing Profile's record policy: what is captured for each signing
 * operation, how long it is retained, and how it is persisted.
 *
 *
 * @param recordMetadata        Whether operation metadata is recorded.
 * @param recordRequestMetadata Whether request metadata is recorded.
 * @param recordSignature       Whether the produced signature is recorded.
 * @param recordSignedDocument  Whether the signed document is recorded.
 * @param recordDtbs            Whether the data-to-be-signed is recorded.
 * @param retentionDays         Number of days records are retained, or {@code null} for indefinite retention.
 * @param deleteAfterRetrieval  Whether a record is deleted once it has been retrieved.
 * @param persistenceMode       How records are persisted.
 */
public record SigningRecordPolicyModel(
        boolean recordMetadata,
        boolean recordRequestMetadata,
        boolean recordSignature,
        boolean recordSignedDocument,
        boolean recordDtbs,
        Integer retentionDays,
        boolean deleteAfterRetrieval,
        SigningRecordPersistenceMode persistenceMode
) {
}
