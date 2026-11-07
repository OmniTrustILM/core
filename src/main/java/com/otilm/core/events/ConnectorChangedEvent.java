package com.otilm.core.events;

import java.util.UUID;

/**
 * Published when a connector changes, inside the changing transaction when there is one, so caches of what Core read
 * from the connector can forget it. A listener evicts through {@code CacheEvictor}, which waits for the commit.
 */
public record ConnectorChangedEvent(UUID connectorUuid) {
}
