package com.otilm.core.model.crypto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.attribute.MetadataIdentifier;
import com.otilm.core.model.IdentifiableModel;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** Provider-owned key identity, interpreted in the context of its connector and token. */
public sealed interface RemoteKeyReference {

    /**
     * Returns the provider UUID or a description of the metadata handle using {@link MetadataIdentifier}. Metadata
     * output is diagnostic text, not a serialized handle suitable for a provider request.
     *
     * @return a UUID or prefixed metadata names and permitted scalar values
     */
    String toIdentifierString();

    /**
     * Provider-owned UUID reference.
     *
     * @param uuid the provider's non-null key UUID
     */
    record UuidReference(UUID uuid) implements RemoteKeyReference, IdentifiableModel {

        @Override
        public String toIdentifierString() {
            return IdentifiableModel.super.toIdentifierString();
        }
    }

    /**
     * Opaque durable key handle returned by a stateless provider.
     *
     * @param keyMeta metadata supplied by the provider; null or empty metadata is rendered as an empty set of
     * attributes
     */
    record MetadataReference(List<MetadataAttribute> keyMeta) implements RemoteKeyReference {

        private static final ObjectWriter KEY_ORDERED_WRITER = ObjectMapperFactory
                .storage()
                .writer()
                .with(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

        /**
         * Includes attribute names and permitted scalar values for provider-side correlation.
         *
         * @return {@code key metadata reference } followed by formatted metadata
         */
        @Override
        public String toIdentifierString() {
            return "key metadata reference " + MetadataIdentifier.format(keyMeta);
        }

        /**
         * The lowercase hex SHA-256 of each attribute's name and content data. Attribute order and decorations take no
         * part, but the order of an attribute's content data does.
         *
         * @return the digest, or null for an empty handle, which identifies no key
         */
        public String digest() {
            if (keyMeta == null || keyMeta.isEmpty()) {
                return null;
            }
            List<NameAndValues> attributesInCanonicalOrder = keyMeta
                    .stream()
                    .map(NameAndValues::of)
                    .sorted(Comparator.comparing(MetadataReference::canonicalJson))
                    .toList();
            try {
                return HexFormat
                        .of()
                        .formatHex(MessageDigest
                                .getInstance("SHA-256")
                                .digest(canonicalJson(attributesInCanonicalOrder).getBytes(StandardCharsets.UTF_8)));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is not available", e);
            }
        }

        private static String canonicalJson(Object value) {
            try {
                return KEY_ORDERED_WRITER.writeValueAsString(value);
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("A key handle could not be rendered for its digest", e);
            }
        }

        @JsonPropertyOrder({"name", "data"})
        private record NameAndValues(String name, List<Object> data) {

            static NameAndValues of(MetadataAttribute attribute) {
                List<AttributeContent> content = attribute.getContent();
                List<Object> data = content == null
                        ? List.of()
                        : content.stream().<Object>map(AttributeContent::getData).toList();
                return new NameAndValues(attribute.getName(), data);
            }
        }
    }
}
