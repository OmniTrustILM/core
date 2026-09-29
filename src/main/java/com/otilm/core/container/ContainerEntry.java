package com.otilm.core.container;

import com.otilm.api.model.client.inspection.InspectedEntryKind;

/** One entry of an uploaded file, named by a reference derived from its own content rather than its position. */
public sealed interface ContainerEntry permits CertificateEntry, KeyEntry, SigningRequestEntry {

    /**
     * The entry's reference: the lowercase hex SHA-256 of the DER that identifies it.
     *
     * @return the reference
     */
    String reference();

    /**
     * What the entry is.
     *
     * @return the entry's kind
     */
    InspectedEntryKind kind();
}
