package com.otilm.core.util.builders;

import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningRecord;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Builds an in-memory {@link SigningRecord} with valid, unremarkable defaults; tests override only the fields
 * whose values drive the assertion under test. Persistence goes through {@code SigningRecordWriter}, not this
 * builder — the builder never touches the database.
 */
public class SigningRecordEntityBuilder {

    private SigningProfileDto signingProfile = null;
    private UUID signingProfileUuid = null;
    private int version = 1;
    private SigningProtocol protocol = SigningProtocol.TSP;
    private String name = null;
    private Instant signingTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    private byte[] signatureValue = null;
    private byte[] dtbs = null;
    private byte[] signedDocument = null;
    private String requestMetadataJson = null;
    private UUID requestedByUuid = null;
    private String requestedByUsername = null;
    private Instant signedDocumentRetrievedAt = null;

    public static SigningRecordEntityBuilder aSigningRecord() {
        return new SigningRecordEntityBuilder();
    }

    public SigningRecordEntityBuilder withSigningProfile(SigningProfileDto profile) {
        this.signingProfile = profile;
        return this;
    }

    public SigningRecordEntityBuilder withSigningProfileUuid(UUID signingProfileUuid) {
        this.signingProfileUuid = signingProfileUuid;
        return this;
    }

    public SigningRecordEntityBuilder withVersion(int version) {
        this.version = version;
        return this;
    }

    public SigningRecordEntityBuilder withProtocol(SigningProtocol protocol) {
        this.protocol = protocol;
        return this;
    }

    public SigningRecordEntityBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public SigningRecordEntityBuilder withSigningTime(Instant time) {
        this.signingTime = time;
        return this;
    }

    public SigningRecordEntityBuilder withSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    public SigningRecordEntityBuilder withDtbs(byte[] dtbs) {
        this.dtbs = dtbs;
        return this;
    }

    public SigningRecordEntityBuilder withSignedDocument(byte[] signedDocument) {
        this.signedDocument = signedDocument;
        return this;
    }

    public SigningRecordEntityBuilder withRequestMetadataJson(String requestMetadataJson) {
        this.requestMetadataJson = requestMetadataJson;
        return this;
    }

    public SigningRecordEntityBuilder withRequestedByUuid(UUID requestedByUuid) {
        this.requestedByUuid = requestedByUuid;
        return this;
    }

    public SigningRecordEntityBuilder withRequestedByUsername(String requestedByUsername) {
        this.requestedByUsername = requestedByUsername;
        return this;
    }

    public SigningRecordEntityBuilder withSignedDocumentRetrievedAt(Instant signedDocumentRetrievedAt) {
        this.signedDocumentRetrievedAt = signedDocumentRetrievedAt;
        return this;
    }

    public SigningRecord build() {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setUuid(UUID.randomUUID());
        UUID profileUuid = signingProfileUuid != null
                ? signingProfileUuid
                : (signingProfile != null ? UUID.fromString(signingProfile.getUuid()) : null);
        if (profileUuid != null) {
            signingRecord.setSigningProfileUuid(profileUuid);
        }
        signingRecord.setName(name != null ? name : (signingProfile != null ? signingProfile.getName() : null));
        signingRecord.setSigningProfileVersion(version);
        signingRecord.setProtocol(protocol);
        signingRecord.setSigningTime(signingTime);
        signingRecord.setSignatureValue(signatureValue);
        signingRecord.setDtbs(dtbs);
        signingRecord.setSignedDocument(signedDocument);
        signingRecord.setRequestMetadataJson(requestMetadataJson);
        signingRecord.setRequestedByUuid(requestedByUuid);
        signingRecord.setRequestedByUsername(requestedByUsername);
        signingRecord.setSignedDocumentRetrievedAt(signedDocumentRetrievedAt);
        return signingRecord;
    }
}
