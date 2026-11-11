package com.otilm.core.signing.record;

import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import java.util.List;
import java.util.UUID;

/**
 * A persistence-mode strategy for recording a signing operation. Each implementation owns one
 * {@link com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode} — how durably and how
 * synchronously the record is written — and delegates the actual database work to the single transactional
 * {@link SigningRecordWriter}.
 */
public interface SigningRecordStrategy {

    /**
     * Records the operations of one batch, building each source's input only when the profile records. A durable mode
     * writes all of them or none.
     *
     * @param signingProfile the signing profile every operation of the batch ran on
     * @return the UUIDs of the records in source order, or an empty list when the profile records nothing
     */
    List<UUID> recordSigning(SigningProfileModel<?, ?> signingProfile, List<SigningRecordInputSource> sources);
}
