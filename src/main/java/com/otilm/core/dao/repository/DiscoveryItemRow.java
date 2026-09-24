package com.otilm.core.dao.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of the items listing, normalized across the two stores a run stages into (see {@code DiscoveryDetailCounts}
 * for the split). The API hides it, so both branches of the union project this shape.
 *
 * <p>
 * {@code payload} and {@code meta} arrive as JSON text rather than mapped objects: the certificate branch builds its
 * payload at read time from {@code certificate_content}, so there is no column for Hibernate to map.
 */
public interface DiscoveryItemRow {

    UUID getUuid();

    /** The inventory object this item became, or null while it is unprocessed or failed. */
    UUID getInventoryUuid();

    /** What that object is called, joined from the resource's own table; null wherever the uuid is. */
    String getInventoryName();

    /** Synthesized for a v1 row; see {@code DiscoveryCertificate#sequence}. */
    long getSequence();

    /** Synthesized from the certificate fingerprint for a v1 row. */
    String getUniqueRef();

    /** The enum member name, which is the form both stores hold; it is not published on the wire. */
    String getResource();

    /** An instant, not an offset date-time: the driver hands a timestamptz back without a zone to preserve. */
    Instant getDiscoveredAt();

    String getPayload();

    boolean isNewlyDiscovered();

    boolean isProcessed();

    String getProcessedError();

    String getMeta();
}
