package com.otilm.core.events.handlers.discovery;

import com.otilm.core.dao.entity.Discovery;

import java.util.UUID;

/**
 * The discovery's identity, as recorded against a certificate's metadata and event history.
 *
 * <p>
 * Exists so neither the download phase nor post-processing has to pass the {@code Discovery} entity itself. One
 * detached instance mutated and saved from parallel workers corrupts progress reporting and rolls back committed
 * certificate work, so the entity must not cross into either phase — this is the canonical statement of that
 * constraint, referred to from {@link DiscoveryRunContext} and the discovery writer.
 */
public record DiscoverySource(UUID discoveryUuid, String discoveryName, UUID connectorUuid, String connectorName,
        String discoveryKind) {

    public static DiscoverySource of(DiscoveryRunContext context) {
        return new DiscoverySource(context.discoveryUuid(), context.discoveryName(), context.connectorUuid(),
                context.connectorName(), context.discoveryKind());
    }

    public static DiscoverySource of(Discovery discovery) {
        return new DiscoverySource(discovery.getUuid(), discovery.getName(), discovery.getConnectorUuid(),
                discovery.getConnectorName(), discovery.getKind());
    }
}
