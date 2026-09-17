package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.attribute.MetadataIdentifier;
import com.otilm.core.model.IdentifiableModel;
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

        /**
         * Includes attribute names and permitted scalar values for provider-side correlation.
         *
         * @return {@code key metadata reference } followed by formatted metadata
         */
        @Override
        public String toIdentifierString() {
            return "key metadata reference " + MetadataIdentifier.format(keyMeta);
        }
    }
}
