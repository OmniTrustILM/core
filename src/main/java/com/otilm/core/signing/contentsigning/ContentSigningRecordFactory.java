package com.otilm.core.signing.contentsigning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.record.DeferredSigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.TimestampTokenSerialNumbers;
import com.otilm.core.util.AuthHelper;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Builds the signing-record input for a content-signing run. {@code requestedBy} is the identity on the thread that
 * produced the signature, so the record names who asked for it; it stays unset when that thread carries no identity.
 */
@Component
public class ContentSigningRecordFactory {

    private final ObjectMapper objectMapper;

    public ContentSigningRecordFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Defers assembly — notably the metadata serialization — until recording is known to be on.
     *
     * @param dtbs the data-to-be-signed, or {@code null} for an augmented document Core did not sign
     * @param signatureValue the signature Core produced, or {@code null} for the same reason
     */
    public SigningRecordInputSource source(SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SignedContent result, byte[] dtbs, byte[] signatureValue,
            Instant signingTime, SigningProtocol protocol) {
        return new DeferredSigningRecordInputSource(signingProfile,
                () -> build(signingProfile, profile, result, dtbs, signatureValue, signingTime, protocol));
    }

    private SigningRecordInput build(SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SignedContent result, byte[] dtbs, byte[] signatureValue,
            Instant signingTime, SigningProtocol protocol) {
        return SigningRecordInput
                .builder()
                .signingProfile(signingProfile)
                .protocol(protocol)
                .signingTime(signingTime)
                .requestedBy(AuthHelper.getActingUserOrNull())
                .displayName("%s %s".formatted(signingProfile.name(), result.level().getFormatName(profile.family())))
                .requestMetadataJson(buildRequestMetadataJson(signingProfile, profile, result))
                .signedDocument(result.signedDocument())
                .signature(signatureValue)
                .dtbs(dtbs)
                .timestampTokenSerialNumbers(TimestampTokenSerialNumbers.hex(result.timestampSerials()))
                .build();
    }

    /** Repeats the serials the record carries in its own column, for an operator who has metadata recording on. */
    private String buildRequestMetadataJson(SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SignedContent result) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("signingProfileName", signingProfile.name());
        metadata.put("signingProfileVersion", signingProfile.version());
        metadata.put("family", profile.family().name());
        metadata.put("signatureLevel", result.level().name());
        metadata.put("timestampTokenSerialNumbers", TimestampTokenSerialNumbers.hex(result.timestampSerials()));
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize content-signing record request metadata", e);
        }
    }

}
