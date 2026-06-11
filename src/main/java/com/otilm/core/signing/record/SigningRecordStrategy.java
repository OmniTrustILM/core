package com.otilm.core.signing.record;

import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;

/**
 * A persistence-mode strategy for recording a signing operation. Each implementation owns one
 * {@link com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode} — how durably and
 * how synchronously the record is written — and delegates the actual database work to the single transactional
 * {@link SigningRecordWriter}.
 */
public interface SigningRecordStrategy {
    void recordSigning(SigningRecordInput input);
}
