package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * What makes a later import request the same import as an earlier one: the requester, the token profile, the file, the
 * key it holds, and the terms the connector is asked to import it under. The attributes are read in name order, so a
 * retry that lists them differently is still the same import.
 */
final class ImportIdempotencyKey {

    private static final ObjectMapper CANONICAL = ObjectMapperFactory.canonical();

    private ImportIdempotencyKey() {
    }

    static String of(KeyImportTerms terms, byte[] file) {
        String identity = String
                .join("\n", terms.requester().getUuid(), terms.profile().uuid().toString(), sha256(file),
                        terms.spkiFingerprint(), Boolean.toString(terms.exportable()),
                        sha256(canonicalJson(terms.importAttributes())));
        return sha256(identity.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] canonicalJson(List<RequestAttribute> attributes) {
        List<RequestAttribute> ordered = attributes
                .stream()
                .sorted(Comparator
                        .comparing(RequestAttribute::getName, Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();
        try {
            return CANONICAL.writeValueAsBytes(ordered);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The import attributes could not be serialized.", e);
        }
    }

    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }
}
