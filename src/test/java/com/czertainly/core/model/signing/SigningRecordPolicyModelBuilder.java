package com.czertainly.core.model.signing;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;

public final class SigningRecordPolicyModelBuilder {

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
     * A builder pre-configured to capture no content about a signing operation.
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
                recordRequestMetadata,
                recordSignature,
                recordSignedDocument,
                recordDtbs,
                retentionDays,
                deleteAfterRetrieval,
                persistenceMode);
    }
}
