package com.otilm.core.model.signing;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;

public final class SigningRecordPolicyModelBuilder {

    private boolean recordingEnabled = true;
    private boolean recordRequestMetadata = false;
    private boolean recordSignature = false;
    private boolean recordSignedDocument = false;
    private boolean recordDtbs = false;
    private Integer retentionDays = null;
    private boolean deleteAfterRetrieval = false;
    private SigningRecordPersistenceMode persistenceMode = SigningRecordPersistenceMode.DEFERRED_DURABLE;

    public static SigningRecordPolicyModelBuilder aSigningRecordPolicy() {
        return new SigningRecordPolicyModelBuilder();
    }

    /**
     * A builder pre-configured with recording disabled entirely: no record is created at all, regardless of
     * the content flags.
     */
    public static SigningRecordPolicyModelBuilder recordingDisabled() {
        return aSigningRecordPolicy().recordingEnabled(false);
    }

    /**
     * A builder pre-configured with recording enabled but capturing no optional content about a signing
     * operation: a metadata-only record (who, when, profile/version) is still created.
     */
    public static SigningRecordPolicyModelBuilder notRecording() {
        return aSigningRecordPolicy()
                .recordRequestMetadata(false)
                .recordSignature(false)
                .recordSignedDocument(false)
                .recordDtbs(false);
    }

    /**
     * A builder pre-configured to capture every recordable content type.
     */
    public static SigningRecordPolicyModelBuilder recordingEverything() {
        return aSigningRecordPolicy()
                .recordRequestMetadata(true)
                .recordSignature(true)
                .recordSignedDocument(true)
                .recordDtbs(true);
    }

    public SigningRecordPolicyModelBuilder recordingEnabled(boolean v) {
        this.recordingEnabled = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder recordRequestMetadata(boolean v) {
        this.recordRequestMetadata = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder recordSignature(boolean v) {
        this.recordSignature = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder recordSignedDocument(boolean v) {
        this.recordSignedDocument = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder recordDtbs(boolean v) {
        this.recordDtbs = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder retentionDays(Integer v) {
        this.retentionDays = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder deleteAfterRetrieval(boolean v) {
        this.deleteAfterRetrieval = v;
        return this;
    }

    public SigningRecordPolicyModelBuilder persistenceMode(SigningRecordPersistenceMode v) {
        this.persistenceMode = v;
        return this;
    }

    public SigningRecordPolicyModel build() {
        return new SigningRecordPolicyModel(
                recordingEnabled,
                recordRequestMetadata,
                recordSignature,
                recordSignedDocument,
                recordDtbs,
                retentionDays,
                deleteAfterRetrieval,
                persistenceMode);
    }
}
