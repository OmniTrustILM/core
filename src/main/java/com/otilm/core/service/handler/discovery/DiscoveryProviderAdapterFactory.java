package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Dispatches discovery operations to the adapter matching the run's connector interface version.
 *
 * <p>
 * A run with no connector-interface association is a v1 run — the deliberate inverse of
 * {@code AuthorityProviderAdapterFactory}'s NULL rule, because discovery's legacy is the v1 interface: every run
 * created before the v2 create path exists carries no association. Any unrecognized version refuses rather than
 * guessing.
 */
@Component
public class DiscoveryProviderAdapterFactory {

    private final DiscoveryProviderV1Adapter v1Adapter;
    private final DiscoveryProviderV2Adapter v2Adapter;
    private final ConnectorInterfaceRepository connectorInterfaceRepository;

    public DiscoveryProviderAdapterFactory(DiscoveryProviderV1Adapter v1Adapter, DiscoveryProviderV2Adapter v2Adapter,
            ConnectorInterfaceRepository connectorInterfaceRepository) {
        this.v1Adapter = v1Adapter;
        this.v2Adapter = v2Adapter;
        this.connectorInterfaceRepository = connectorInterfaceRepository;
    }

    /**
     * Selects the adapter for the run. {@code null} tolerated on purpose: the caller may not have been able to load the
     * run (asynchronous start against a deleted uuid), and that failure belongs to the v1 flow's established handling,
     * not to routing.
     */
    public DiscoveryProviderAdapter forDiscovery(Discovery discovery) {
        return discovery == null
                ? v1Adapter
                : forConnectorInterface(discovery.getConnectorInterfaceUuid(), discovery.getUuid());
    }

    /**
     * Selects the adapter from the association alone, for a caller that has no reason to load the run — dispatch only
     * needs to know which generation to hand it to.
     *
     * <p>
     * Kept scalar: dispatch runs in a {@code NOT_SUPPORTED} scope whose reads share one {@code EntityManager}, so
     * loading the run there parks it in a first-level cache that a later read in the same scope answers from, long
     * after another transaction has changed the row.
     *
     * @param connectorInterfaceUuid the run's association, or {@code null} for a v1 run
     * @param discoveryUuid names the run in a refusal; it is not read
     */
    public DiscoveryProviderAdapter forConnectorInterface(UUID connectorInterfaceUuid, UUID discoveryUuid) {
        if (connectorInterfaceUuid == null) {
            return v1Adapter;
        }
        ConnectorInterfaceEntity iface = connectorInterfaceRepository
                .findById(connectorInterfaceUuid)
                .orElseThrow(() -> new UnsupportedDiscoveryVersionException(
                        "Discovery connector interface not found (discovery " + discoveryUuid + ")"));
        String version = iface.getVersion();
        if (version == null) {
            throw new UnsupportedDiscoveryVersionException(
                    "Discovery connector interface has no version (discovery " + discoveryUuid + ")");
        }
        if ("v2".equals(version)) {
            return v2Adapter;
        }
        throw new UnsupportedDiscoveryVersionException(
                "Unsupported discovery connector interface version: " + version + " (discovery " + discoveryUuid + ")");
    }
}
