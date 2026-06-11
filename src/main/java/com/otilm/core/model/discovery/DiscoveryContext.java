package com.otilm.core.model.discovery;

import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.DiscoveryHistory;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class DiscoveryContext {
    private final UUID loggedUserUuid;
    private final ConnectorDto connectorDto;
    private final DiscoveryHistory discoveryHistory;
    private final List<DataAttribute> dataAttributes;

    private String message;
    private DiscoveryStatus discoveryStatus;
    private DiscoveryStatus connectorDiscoveryStatus;
    private int certificatesDiscovered;
    private int connectorCertificatesDiscovered;

    private List<MetadataAttribute> metadata;

    public DiscoveryContext(UUID loggedUserUuid, ConnectorDto connectorDto, DiscoveryHistory discoveryHistory, List<DataAttribute> dataAttributes) {
        this.loggedUserUuid = loggedUserUuid;
        this.connectorDto = connectorDto;
        this.discoveryHistory = discoveryHistory;
        this.dataAttributes = dataAttributes;
    }

    public void setDiscoveryFailed(String message) {
        this.discoveryStatus = DiscoveryStatus.FAILED;
        this.connectorDiscoveryStatus = DiscoveryStatus.FAILED;
        this.message = message;
    }
}
