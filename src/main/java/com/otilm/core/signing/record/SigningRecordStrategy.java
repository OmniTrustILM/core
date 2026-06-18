package com.otilm.core.signing.record;

import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;

/**
 * A persistence-mode strategy for recording a signing operation. Each implementation owns one
 * {@link com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode} — how durably and
 * how synchronously the record is written — and delegates the actual database work to the single transactional
 * {@link SigningRecordWriter}.
 */
public interface SigningRecordStrategy {

    /**
     * Records a signing operation supplied as a deferred {@link SigningRecordInputSource}: the
     * {@code recordingEnabled} gate and intake metrics are evaluated from the source's signing profile, and the
     * full input is materialized only once recording is known to be on.
     */
    void recordSigning(SigningRecordInputSource source);
}
