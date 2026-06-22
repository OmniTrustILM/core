package com.otilm.core.signing.tsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.record.DeferredSigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@link SigningRecordInput} for a granted RFC 3161 timestamp from the signing profile, the
 * request, and the artifacts produced during token assembly.
 *
 * <p>The per-field {@code record*} content toggles are applied downstream by the signing-record mapper, which is
 * the single source of truth for what gets persisted; this factory only assembles the full input, including
 * {@code requestMetadataJson}, unconditionally.
 *
 * <p>{@code requestedBy} is left {@code null}: the TSP caller identity is resolved in the protocol layer and is
 * not currently threaded down to the TSA engine.
 */
@Component
public class TspSigningRecordFactory {

    private final ObjectMapper objectMapper;

    public TspSigningRecordFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Returns a deferred {@link SigningRecordInputSource} over the same arguments as {@link #build}: the signing
     * profile is exposed immediately for the recording gate, but the full input — including the
     * {@code requestMetadataJson} serialization — is assembled only when {@link SigningRecordInputSource#build()}
     * is called, so disabled profiles never pay for it.
     */
    public SigningRecordInputSource source(SigningProfileModel<?, ?> signingProfile, TspRequest request,
                                           BigInteger serialNumber, Instant genTime, byte[] encodedToken) {
        return new DeferredSigningRecordInputSource(signingProfile,
                () -> build(signingProfile, request, serialNumber, genTime, encodedToken));
    }

    private SigningRecordInput build(SigningProfileModel<?, ?> signingProfile, TspRequest request,
                                     BigInteger serialNumber, Instant genTime, byte[] encodedToken) {
        String serialHex = serialNumber.toString(16);

        // The timestamp token is the self-contained signed artifact: it already embeds the signature value and the
        // signed attributes (DTBS), so both are recoverable from it. Storing them again under signature/dtbs would
        // duplicate substrings of the token, so only signedDocument is populated for the TSP path.
        return SigningRecordInput.builder()
                .signingProfile(signingProfile)
                .protocol(SigningProtocol.TSP)
                .signingTime(genTime)
                .requestedBy(null)
                .displayName(signingProfile.name() + " #" + serialHex)
                .requestMetadataJson(buildRequestMetadataJson(signingProfile, request, serialHex))
                .signedDocument(encodedToken)
                .build();
    }

    private String buildRequestMetadataJson(SigningProfileModel<?, ?> signingProfile, TspRequest request, String serialHex) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("signingProfileName", signingProfile.name());
        metadata.put("signingProfileVersion", signingProfile.version());
        metadata.put("serialNumber", serialHex);
        metadata.put("hashAlgorithm", request.hashAlgorithm() != null ? request.hashAlgorithm().name() : null);
        metadata.put("policy", request.policy().orElse(null));
        metadata.put("nonce", request.nonce().map(BigInteger::toString).orElse(null));
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize TSP signing-record request metadata", e);
        }
    }
}
