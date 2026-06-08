package com.czertainly.core.signing.record;

/**
 * A persistence-mode strategy for recording a signing operation. Each implementation owns one
 * {@link com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode} — how durably and
 * how synchronously the record is written — and delegates the actual database work to the single transactional
 * {@link com.czertainly.core.service.writer.signingrecord.SigningRecordWriter}.
 */
public interface SigningRecordStrategy {
    void recordSigning(SigningRecordInput input);
}
