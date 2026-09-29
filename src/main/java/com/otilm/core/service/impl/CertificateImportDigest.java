package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.core.container.EntryReference;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * What makes a later request's entry the same import as an earlier one: the entry, where its key goes and the custom
 * attributes its certificates get. The passphrase only opens the file, so it is not part of it. The profile is read as
 * the UUID it names, the attributes in name order, and an absent list or exportability as its default, so a retry that
 * states them differently is still the same import.
 */
final class CertificateImportDigest {

    private static final ObjectMapper CANONICAL = ObjectMapperFactory.canonical();

    private CertificateImportDigest() {
    }

    /**
     * SHA-256 over the entry's reference, destination and the request's certificate custom attributes, canonically
     * ordered. The canonical form is overwritten once it is hashed.
     *
     * @throws IllegalArgumentException if the destination's profile is not a UUID
     */
    static String of(CertificateImportEntryDto entry, List<RequestAttribute> certificateCustomAttributes) {
        CertificateEntryKeyDestinationDto destination = entry.getKeyDestination();
        Terms terms = new Terms(entry.getEntryReference(), destination == null ? null : Destination.of(destination),
                ordered(certificateCustomAttributes));
        byte[] canonical = canonical(terms);
        try {
            return EntryReference.of(canonical);
        } finally {
            Arrays.fill(canonical, (byte) 0);
        }
    }

    private static byte[] canonical(Terms terms) {
        try {
            return CANONICAL.writeValueAsBytes(terms);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The import terms could not be serialized.", e);
        }
    }

    private static List<RequestAttribute> ordered(List<RequestAttribute> attributes) {
        if (attributes == null) {
            return List.of();
        }
        return attributes
                .stream()
                .sorted(Comparator
                        .comparing(RequestAttribute::getName, Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();
    }

    private record Terms(String entryReference, Destination keyDestination,
            List<RequestAttribute> certificateCustomAttributes) {
    }

    /** The destination as it decides the import, the key name as given. */
    private record Destination(UUID tokenProfileUuid, String keyName, boolean exportable,
            List<RequestAttribute> importAttributes, List<RequestAttribute> customAttributes) {

        static Destination of(CertificateEntryKeyDestinationDto destination) {
            return new Destination(UUID.fromString(destination.getTokenProfileUuid()), destination.getKeyName(),
                    Boolean.TRUE.equals(destination.getExportable()), ordered(destination.getImportAttributes()),
                    ordered(destination.getCustomAttributes()));
        }
    }
}
