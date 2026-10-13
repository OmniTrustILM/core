package com.otilm.core.model.discovery;

import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DiscoveryContext {
    private final UUID loggedUserUuid;
    private final ConnectorDto connectorDto;
    private final Discovery discovery;
    private final List<DataAttribute> dataAttributes;

    private String message;
    private DiscoveryStatus discoveryStatus;
    private DiscoveryStatus connectorDiscoveryStatus;
    private int certificatesDiscovered;
    private int connectorCertificatesDiscovered;

    private List<MetadataAttribute> metadata;

    /** The run's metadata has been offered to the engine, whatever came of it; it is stored once per run. */
    private boolean runMetadataHandled;
    /** The engine could not store the run's metadata. Advisory: the run's outcome stands, its message says so. */
    private boolean runMetadataNotStored;

    public DiscoveryContext(UUID loggedUserUuid, ConnectorDto connectorDto, Discovery discovery,
            List<DataAttribute> dataAttributes) {
        this.loggedUserUuid = loggedUserUuid;
        this.connectorDto = connectorDto;
        this.discovery = discovery;
        this.dataAttributes = dataAttributes;
    }

    public void setDiscoveryFailed(String message) {
        this.discoveryStatus = DiscoveryStatus.FAILED;
        this.connectorDiscoveryStatus = DiscoveryStatus.FAILED;
        this.message = message;
    }
}
