package com.otilm.core.signing.rawsigning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.signing.record.DeferredSigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.clocksource.ClockSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Builds the signing-record inputs of a raw signing run, one per digest. Every record of a run carries the same signing
 * time and requester, because the provider signed the batch in one call for one caller.
 */
@Component
public class RawSigningRecordFactory {

    private final ObjectMapper objectMapper;
    private final ClockSource clockSource;

    public RawSigningRecordFactory(ObjectMapper objectMapper, ClockSource clockSource) {
        this.objectMapper = objectMapper;
        this.clockSource = clockSource;
    }

    /**
     * Reads the signing time and the requester now, on the thread that signed, and defers the rest of each input until
     * recording is known to be on; call it once the batch is signed, so the time follows the signatures. The algorithms
     * go into the request metadata, kept only when the profile records it; the profile version's certificate and
     * signing attributes name them either way.
     *
     * @param items the digests in request order
     * @param signatures the signature of each digest, in the same order
     * @return one source per digest, in request order
     */
    public List<SigningRecordInputSource> sources(SigningProfileModel<?, ?> signingProfile, List<RawSigningItem> items,
            List<byte[]> signatures, SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm,
            SigningProtocol protocol) {
        if (items.size() != signatures.size()) {
            throw new IllegalArgumentException(
                    "%d signatures for %d digests".formatted(signatures.size(), items.size()));
        }
        Instant signingTime = clockSource.wallTimeInstant();
        NameAndUuidDto requestedBy = AuthHelper.getActingUserOrNull();
        Map<String, Object> requestMetadata = requestMetadata(signingProfile, signatureAlgorithm, digestAlgorithm);
        List<SigningRecordInputSource> sources = new ArrayList<>(items.size());
        for (int index = 0; index < items.size(); index++) {
            RawSigningItem item = items.get(index);
            byte[] signature = signatures.get(index);
            sources
                    .add(new DeferredSigningRecordInputSource(signingProfile, () -> build(signingProfile, item,
                            signature, signingTime, requestedBy, protocol, requestMetadata)));
        }
        return sources;
    }

    private SigningRecordInput build(SigningProfileModel<?, ?> signingProfile, RawSigningItem item, byte[] signature,
            Instant signingTime, NameAndUuidDto requestedBy, SigningProtocol protocol,
            Map<String, Object> requestMetadata) {
        return SigningRecordInput
                .builder()
                .signingProfile(signingProfile)
                .protocol(protocol)
                .signingTime(signingTime)
                .requestedBy(requestedBy)
                .displayName("%s digest '%s'".formatted(signingProfile.name(), item.identifier()))
                .requestMetadataJson(serialize(requestMetadata))
                .dtbs(item.digest())
                .signature(signature)
                .build();
    }

    private static Map<String, Object> requestMetadata(SigningProfileModel<?, ?> signingProfile,
            SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("signingProfileName", signingProfile.name());
        metadata.put("signingProfileVersion", signingProfile.version());
        metadata.put("signatureAlgorithm", signatureAlgorithm.getCode());
        metadata.put("digestAlgorithm", digestAlgorithm.getCode());
        return metadata;
    }

    private String serialize(Map<String, Object> requestMetadata) {
        try {
            return objectMapper.writeValueAsString(requestMetadata);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize raw-signing record request metadata", e);
        }
    }
}
