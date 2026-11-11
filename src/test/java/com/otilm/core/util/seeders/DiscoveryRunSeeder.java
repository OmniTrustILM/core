package com.otilm.core.util.seeders;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.util.DiscoveryInterfaceFixture;
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

    public Discovery seedV2Run(DiscoveryStatus status) {
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        return discoveryRepository.saveAndFlush(run);
    }
}
