package com.otilm.core.model.discovery;

/**
 * The kinds of pending work a discovery v2 run can owe in {@code discovery_work}: polling the connector's run status,
 * draining staged result pages, and processing drained items into inventory. Which types coexist is the tick workers'
 * contract, not the table's.
 */
public enum DiscoveryWorkType {
    STATUS,
    DRAIN,
    PROCESS
}
