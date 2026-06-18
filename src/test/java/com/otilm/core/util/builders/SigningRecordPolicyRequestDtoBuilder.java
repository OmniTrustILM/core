package com.otilm.core.util.builders;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;

public class SigningRecordPolicyRequestDtoBuilder {

    private boolean recordingEnabled = true;
    private boolean recordRequestMetadata = false;
    private boolean recordSignature = false;
    private boolean recordSignedDocument = false;
    private boolean recordDtbs = false;
    private Integer retentionDays = null;
    private boolean deleteAfterRetrieval = false;
    private SigningRecordPersistenceMode persistenceMode = SigningRecordPersistenceMode.DEFERRED_DURABLE;

    public static SigningRecordPolicyRequestDtoBuilder aSigningRecordPolicyRequest() {
        return new SigningRecordPolicyRequestDtoBuilder();
    }

    /**
     * A builder pre-configured to capture every recordable content type.
     */
    public static SigningRecordPolicyRequestDtoBuilder recordingEverything() {
        return aSigningRecordPolicyRequest()
                .withRecordRequestMetadata(true)
                .withRecordSignature(true)
                .withRecordSignedDocument(true)
                .withRecordDtbs(true);
    }

    public SigningRecordPolicyRequestDtoBuilder withRecordingEnabled(boolean v) {
        this.recordingEnabled = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withRecordRequestMetadata(boolean v) {
        this.recordRequestMetadata = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withRecordSignature(boolean v) {
        this.recordSignature = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withRecordSignedDocument(boolean v) {
        this.recordSignedDocument = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withRecordDtbs(boolean v) {
        this.recordDtbs = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withRetentionDays(Integer v) {
        this.retentionDays = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withDeleteAfterRetrieval(boolean v) {
        this.deleteAfterRetrieval = v;
        return this;
    }

    public SigningRecordPolicyRequestDtoBuilder withPersistenceMode(SigningRecordPersistenceMode v) {
        this.persistenceMode = v;
        return this;
    }

    public SigningRecordPolicyRequestDto build() {
        SigningRecordPolicyRequestDto dto = new SigningRecordPolicyRequestDto();
        dto.setRecordingEnabled(recordingEnabled);
        dto.setRecordRequestMetadata(recordRequestMetadata);
        dto.setRecordSignature(recordSignature);
        dto.setRecordSignedDocument(recordSignedDocument);
        dto.setRecordDtbs(recordDtbs);
        dto.setRetentionDays(retentionDays);
        dto.setDeleteAfterRetrieval(deleteAfterRetrieval);
        dto.setPersistenceMode(persistenceMode);
        return dto;
    }
}
