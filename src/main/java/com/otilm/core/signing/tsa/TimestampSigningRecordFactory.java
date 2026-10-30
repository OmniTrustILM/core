package com.otilm.core.signing.tsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.record.DeferredSigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.TimestampTokenSerialNumbers;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.util.AuthHelper;
import java.math.BigInteger;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Builds the {@link SigningRecordInput} for an issued timestamp from the signing profile, the request, and the
 * artifacts produced during token assembly. The caller supplies the {@link SigningProtocol} so the record distinguishes
 * a client's RFC 3161 request from issuance the platform made on its own.
 *
 * <p>
 * The per-field {@code record*} content toggles are applied downstream by the signing-record mapper, which is the
 * single source of truth for what gets persisted; this factory only assembles the full input, including
 * {@code requestMetadataJson}, unconditionally.
 *
 * <p>
 * {@code requestedBy} is the identity on the thread that issued the token. On the TSP path a TSP authenticator put it
 * into the SecurityContext; in-process issuance has no caller of its own, so the record names whoever requested the
 * signature the timestamp goes into. It stays unset when the issuing thread carries no identity.
 */
@Component
public class TimestampSigningRecordFactory {

    private final ObjectMapper objectMapper;

    public TimestampSigningRecordFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Returns a deferred {@link SigningRecordInputSource} over the same arguments as {@link #build}: the signing
     * profile is exposed immediately for the recording gate, but the full input — including the
     * {@code requestMetadataJson} serialization — is assembled only when {@link SigningRecordInputSource#build()} is
     * called, so disabled profiles never pay for it.
     */
    public SigningRecordInputSource source(SigningProfileModel<?, ?> signingProfile, TspRequest request,
            BigInteger serialNumber, Instant genTime, byte[] encodedToken, SigningProtocol protocol) {
        return new DeferredSigningRecordInputSource(signingProfile,
                () -> build(signingProfile, request, serialNumber, genTime, encodedToken, protocol));
    }

    private SigningRecordInput build(SigningProfileModel<?, ?> signingProfile, TspRequest request,
            BigInteger serialNumber, Instant genTime, byte[] encodedToken, SigningProtocol protocol) {
        String serialHex = TimestampTokenSerialNumbers.hex(serialNumber);

        // The timestamp token is the self-contained signed artifact: it already embeds the signature value and the
        // signed attributes (DTBS), so both are recoverable from it. Storing them again under signature/dtbs would
        // duplicate substrings of the token, so only signedDocument is populated.
        return SigningRecordInput
                .builder()
                .signingProfile(signingProfile)
                .protocol(protocol)
                .signingTime(genTime)
                .requestedBy(AuthHelper.getActingUserOrNull())
                .displayName(signingProfile.name() + " #" + serialHex)
                .requestMetadataJson(buildRequestMetadataJson(signingProfile, request, serialHex))
                .signedDocument(encodedToken)
                .timestampTokenSerialNumbers(List.of(serialHex))
                .build();
    }

    private String buildRequestMetadataJson(SigningProfileModel<?, ?> signingProfile, TspRequest request,
            String serialHex) {
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
