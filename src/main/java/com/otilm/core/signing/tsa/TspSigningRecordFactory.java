package com.otilm.core.signing.tsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@link SigningRecordInput} for a granted RFC 3161 timestamp from the signing profile, the
 * request, and the artifacts produced during token assembly.
 *
 * <p>The per-field {@code record*} content toggles are applied downstream by the signing-record mapper; this
 * factory only assembles the full input. The one exception is {@code requestMetadataJson}, which it builds
 * only when {@link com.otilm.core.model.signing.SigningRecordPolicyModel#recordRequestMetadata()} is on so the
 * JSON serialization is skipped when the metadata would be discarded.
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

    public SigningRecordInput build(SigningProfileModel<?, ?> signingProfile, TspRequest request,
                                    BigInteger serialNumber, Instant genTime, TimeStampToken token) throws IOException {
        String requestMetadataJson = signingProfile.recordPolicy().recordRequestMetadata()
                ? buildRequestMetadataJson(signingProfile, request, serialNumber)
                : null;

        // The timestamp token is the self-contained signed artifact: it already embeds the signature value and the
        // signed attributes (DTBS), so both are recoverable from it. Storing them again under signature/dtbs would
        // duplicate substrings of the token, so only signedDocument is populated for the TSP path.
        return SigningRecordInput.builder()
                .signingProfile(signingProfile)
                .signingTime(genTime)
                .requestedBy(null)
                .displayName(signingProfile.name() + " #" + serialNumber.toString(16))
                .requestMetadataJson(requestMetadataJson)
                .signedDocument(token.getEncoded())
                .build();
    }

    private String buildRequestMetadataJson(SigningProfileModel<?, ?> signingProfile, TspRequest request, BigInteger serialNumber) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("signingProfileName", signingProfile.name());
        metadata.put("signingProfileVersion", signingProfile.version());
        metadata.put("serialNumber", serialNumber.toString(16));
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
