package com.czertainly.core.signing.record;

import com.czertainly.core.model.signing.SigningProfileModel;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;

/**
 * Test builder for {@link SigningRecordInput} pre-populated with valid defaults, so a test only sets
 * the fields relevant to what it asserts.
 */
public final class SigningRecordInputBuilder {

    private SigningProfileModel<?, ?> signingProfile = aSigningProfile().build();
    private Instant signingTime = Instant.parse("2026-01-01T00:00:00Z");
    private String displayName = "test-record";
    private String requestMetadataJson = "{ \"foo\": \"bar\" }";
    private byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
    private byte[] signedDocument = "signed-document".getBytes(StandardCharsets.UTF_8);
    private byte[] dtbs = "data-to-be-signed".getBytes(StandardCharsets.UTF_8);

    public static SigningRecordInputBuilder aSigningRecordInput() {
        return new SigningRecordInputBuilder();
    }

    public SigningRecordInputBuilder signingProfile(SigningProfileModel<?, ?> signingProfile) {
        this.signingProfile = signingProfile;
        return this;
    }

    public SigningRecordInputBuilder signingTime(Instant signingTime) {
        this.signingTime = signingTime;
        return this;
    }

    public SigningRecordInputBuilder displayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    public SigningRecordInputBuilder requestMetadataJson(String requestMetadataJson) {
        this.requestMetadataJson = requestMetadataJson;
        return this;
    }

    public SigningRecordInputBuilder signature(byte[] signature) {
        this.signature = signature;
        return this;
    }

    public SigningRecordInputBuilder signedDocument(byte[] signedDocument) {
        this.signedDocument = signedDocument;
        return this;
    }

    public SigningRecordInputBuilder dtbs(byte[] dtbs) {
        this.dtbs = dtbs;
        return this;
    }

    public SigningRecordInput build() {
        return SigningRecordInput.builder()
                .signingProfile(signingProfile)
                .signingTime(signingTime)
                .displayName(displayName)
                .requestMetadataJson(requestMetadataJson)
                .signature(signature)
                .signedDocument(signedDocument)
                .dtbs(dtbs)
                .build();
    }
}
