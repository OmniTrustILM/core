package com.otilm.core.events.handlers.discovery;

import com.otilm.core.dao.entity.DiscoveryCertificate;

import java.util.List;

/**
 * The rows of one discovery that share a certificate content, and therefore share one certificate.
 *
 * <p>
 * Grouping removes the intra-discovery race: two threads cannot hold the same content, so they cannot both attempt to
 * insert the same certificate.
 */
public record DiscoveryContentGroup(Long certificateContentId, List<DiscoveryCertificate> rows) {
}
