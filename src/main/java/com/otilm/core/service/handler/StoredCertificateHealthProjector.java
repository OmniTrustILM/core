package com.otilm.core.service.handler;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationCheck;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;

/** Projects bounded stored scalars without accessing a managed certificate or running validation. */
public final class StoredCertificateHealthProjector {
    private static final String VALIDATION_CHECK = "validationCheck";
    private static final int MAX_STORED_CHARACTERS = 100000;
    private static final ObjectMapper PARSER = parser();

    private StoredCertificateHealthProjector() {
    }

    public record Snapshot(UUID certificateUuid, UUID raProfileUuid, String commonName, String serialNumber,
            String issuerCommonName, String fingerprint, Date notBefore, Date notAfter, CertificateState state,
            CertificateValidationStatus validationStatus, OffsetDateTime validationTimestamp, String rawChecks) {
    }

    public static StoredCertificateHealth project(Snapshot snapshot) {
        Map<CertificateValidationCheck, CertificateValidationStatus> checks = Map.of();
        var evidence = StoredCertificateHealth.Evidence.MISSING;
        String raw = snapshot.rawChecks();
        // SQL counts code points; supplementary characters use two UTF-16 units in Java.
        if (raw != null && raw.codePointCount(0, raw.length()) > MAX_STORED_CHARACTERS) {
            evidence = StoredCertificateHealth.Evidence.MALFORMED;
        } else if (raw != null && !raw.isBlank()) {
            try {
                checks = decode(raw);
                if (!checks.isEmpty()) {
                    evidence = StoredCertificateHealth.Evidence.PRESENT;
                }
            } catch (Exception failure) {
                evidence = StoredCertificateHealth.Evidence.MALFORMED;
            }
        }
        return new StoredCertificateHealth(snapshot.certificateUuid(), snapshot.raProfileUuid(), snapshot.commonName(),
                snapshot.serialNumber(), snapshot.issuerCommonName(), snapshot.fingerprint(),
                snapshot.notBefore() == null ? null : snapshot.notBefore().toInstant(),
                snapshot.notAfter() == null ? null : snapshot.notAfter().toInstant(), snapshot.state(),
                snapshot.validationStatus(), snapshot.validationTimestamp(), checks, evidence);
    }

    private static Map<CertificateValidationCheck, CertificateValidationStatus> decode(String raw)
            throws java.io.IOException {
        JsonNode root = PARSER.readTree(raw);
        if (!root.isObject()) {
            throw new IllegalArgumentException();
        }
        var checks = new EnumMap<CertificateValidationCheck, CertificateValidationStatus>(
                CertificateValidationCheck.class);
        var entries = root.fields();
        while (entries.hasNext()) {
            var entry = entries.next();
            var check = CertificateValidationCheck.findByCode(entry.getKey());
            JsonNode value = entry.getValue();
            if (!value.isObject() || !value.path("status").isTextual()) {
                throw new IllegalArgumentException();
            }
            if (value.has(VALIDATION_CHECK) && (!value.path(VALIDATION_CHECK).isTextual()
                    || CertificateValidationCheck.findByCode(value.path(VALIDATION_CHECK).textValue()) != check)) {
                throw new IllegalArgumentException();
            }
            checks.put(check, CertificateValidationStatus.findByCode(value.path("status").textValue()));
        }
        return Map.copyOf(checks);
    }

    private static ObjectMapper parser() {
        ObjectMapper mapper = ObjectMapperFactory
                .storage()
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        mapper
                .getFactory()
                .setStreamReadConstraints(StreamReadConstraints
                        .builder()
                        .maxNestingDepth(32)
                        .maxStringLength(2 * MAX_STORED_CHARACTERS)
                        .maxNameLength(128)
                        .maxNumberLength(64)
                        .build());
        return mapper;
    }
}
