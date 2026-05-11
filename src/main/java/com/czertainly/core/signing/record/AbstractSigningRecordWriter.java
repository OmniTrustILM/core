package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import io.micrometer.core.instrument.Timer;

import java.util.UUID;

public abstract class AbstractSigningRecordWriter implements SigningRecordWriter {

    protected final SigningRecordMetrics metrics;

    protected AbstractSigningRecordWriter(SigningRecordMetrics metrics) {
        this.metrics = metrics;
    }

    protected boolean hasAnyRecordableContent(SigningProfileVersion v) {
        return v.isRecordMetadata() || v.isRecordRequestMetadata()
                || v.isRecordSignature() || v.isRecordSignedDocument() || v.isRecordDtbs();
    }

    protected void timed(String mode, Runnable action) {
        Timer.Sample sample = Timer.start(metrics.registry());
        try {
            action.run();
        } finally {
            sample.stop(metrics.writeDuration(mode));
        }
    }

    /**
     * Builds a {@link SigningRecord} with all scalar fields populated from {@code input}.
     * The caller is responsible for setting the signing profile link before persisting.
     */
    protected SigningRecord buildSigningRecord(SigningRecordInput input) {
        SigningProfileVersion v = input.getVersion();
        SigningRecord r = new SigningRecord();
        r.setUuid(UUID.randomUUID());
        r.setName(input.getDisplayName());
        r.setSigningProfileVersion(v.getVersion());
        r.setSigningTime(input.getSigningTime());
        if (v.isRecordRequestMetadata())
            r.setRequestMetadataJson(input.getRequestMetadataJson());
        if (v.isRecordSignature())
            r.setSignatureValue(input.getSignature());
        if (v.isRecordSignedDocument())
            r.setSignedDocument(input.getSignedDocument());
        if (v.isRecordDtbs())
            r.setDtbs(input.getDtbs());
        return r;
    }
}
