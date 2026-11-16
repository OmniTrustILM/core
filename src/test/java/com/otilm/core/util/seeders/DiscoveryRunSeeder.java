package com.otilm.core.util.seeders;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Seeds committed discovery v2 runs: a run row bound to a v2 discovery interface, the shape the tick workers, the sweep
 * and the reaper read. The run has no agenda rows; a test schedules the ones its scenario needs. The interface's
 * connector is not reachable, so a test that lets a run call its connector stubs the client itself.
 */
@Component
public class DiscoveryRunSeeder {

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    /** A run bound to a v2 interface that advertises {@code interfaceFeatures}, for example stop and resume. */
    public Discovery seedV2Run(DiscoveryStatus status, FeatureFlag... interfaceFeatures) {
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository, interfaceFeatures);
        Discovery run = aV2Run(status);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        return discoveryRepository.saveAndFlush(run);
    }

    /**
     * A run Core has created but not yet initiated at its connector: no interface is bound yet, and it targets
     * certificates.
     */
    public Discovery seedUnstartedV2Run() {
        Discovery run = aV2Run(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setResources(List.of(Resource.CERTIFICATE));
        return discoveryRepository.saveAndFlush(run);
    }

    private static Discovery aV2Run(DiscoveryStatus status) {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorName("network-discovery");
        return run;
    }
}
