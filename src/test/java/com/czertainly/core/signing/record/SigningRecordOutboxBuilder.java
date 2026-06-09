package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * Test builder for {@link SigningRecordOutbox} pre-populated with valid defaults, so a test only sets
 * the fields relevant to what it asserts (typically {@code attempts} when exercising poison handling,
 * or the payload fields when exercising the outbox -> signing_record copy).
 */
public final class SigningRecordOutboxBuilder {

    private UUID uuid = UUID.randomUUID();
    private String name = "test-record";
    private UUID signingProfileUuid = UUID.randomUUID();
    private Integer signingProfileVersion = 1;
    private Instant signingTime = Instant.parse("2026-01-01T00:00:00Z");
    private UUID requestedByUuid = UUID.fromString("99999999-9999-9999-9999-999999999999");
    private String requestedByUsername = "alice";
    private byte[] signatureValue = "signature".getBytes(StandardCharsets.UTF_8);
    private byte[] signedDocument = "signed-document".getBytes(StandardCharsets.UTF_8);
    private byte[] dtbs = "data-to-be-signed".getBytes(StandardCharsets.UTF_8);
    private String requestMetadataJson = "{\"correlationId\":\"abc-123\"}";
    private int attempts = 0;
    private String lastError = null;

    public static SigningRecordOutboxBuilder aSigningRecordOutboxRow() {
        return new SigningRecordOutboxBuilder();
    }

    public SigningRecordOutboxBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public SigningRecordOutboxBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public SigningRecordOutboxBuilder withRequestedByUuid(UUID requestedByUuid) {
        this.requestedByUuid = requestedByUuid;
        return this;
    }

    public SigningRecordOutboxBuilder withRequestedByUsername(String requestedByUsername) {
        this.requestedByUsername = requestedByUsername;
        return this;
    }

    public SigningRecordOutboxBuilder withSigningProfileUuid(UUID signingProfileUuid) {
        this.signingProfileUuid = signingProfileUuid;
        return this;
    }

    public SigningRecordOutboxBuilder withSigningProfileVersion(int signingProfileVersion) {
        this.signingProfileVersion = signingProfileVersion;
        return this;
    }

    public SigningRecordOutboxBuilder withSigningTime(Instant signingTime) {
        this.signingTime = signingTime;
        return this;
    }

    public SigningRecordOutboxBuilder withSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    public SigningRecordOutboxBuilder withSignedDocument(byte[] signedDocument) {
        this.signedDocument = signedDocument;
        return this;
    }

    public SigningRecordOutboxBuilder withDtbs(byte[] dtbs) {
        this.dtbs = dtbs;
        return this;
    }

    public SigningRecordOutboxBuilder withRequestMetadataJson(String requestMetadataJson) {
        this.requestMetadataJson = requestMetadataJson;
        return this;
    }

    public SigningRecordOutboxBuilder withAttempts(int attempts) {
        this.attempts = attempts;
        return this;
    }

    public SigningRecordOutboxBuilder withLastError(String lastError) {
        this.lastError = lastError;
        return this;
    }

    public SigningRecordOutbox build() {
        SigningRecordOutbox row = new SigningRecordOutbox();
        row.setUuid(uuid);
        row.setName(name);
        row.setSigningProfileUuid(signingProfileUuid);
        row.setSigningProfileVersion(signingProfileVersion);
        row.setSigningTime(signingTime);
        row.setRequestedByUuid(requestedByUuid);
        row.setRequestedByUsername(requestedByUsername);
        row.setSignatureValue(signatureValue);
        row.setSignedDocument(signedDocument);
        row.setDtbs(dtbs);
        row.setRequestMetadataJson(requestMetadataJson);
        row.setAttempts(attempts);
        row.setLastError(lastError);
        return row;
    }
}
