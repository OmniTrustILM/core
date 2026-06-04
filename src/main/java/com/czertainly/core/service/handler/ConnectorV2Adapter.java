package com.czertainly.core.service.handler;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.connector.v2.*;
import com.czertainly.api.model.core.connector.v2.ConnectInfo;
import com.czertainly.api.model.core.connector.v2.ConnectInfoV2;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.repository.ConnectorInterfaceRepository;
import com.czertainly.core.util.NullUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component(ConnectorVersion.Codes.V2)
public class ConnectorV2Adapter implements ConnectorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorV2Adapter.class);

    private ConnectorApiFactory connectorApiFactory;
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorInterfaceRepository(ConnectorInterfaceRepository connectorInterfaceRepository) {
        this.connectorInterfaceRepository = connectorInterfaceRepository;
    }

    @Override
    public ConnectorVersion getVersion() {
        return ConnectorVersion.V2;
    }

    @Override
    public ConnectorInfo getInfo(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        return connectorApiFactory.getInfoApiClientV2(connectorInfo).getConnectorInfo(connectorInfo).getConnector();
    }

    @Override
    public HealthInfo checkHealth(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        return connectorApiFactory.getHealthApiClientV2(connectorInfo).checkHealth(connectorInfo);
    }

    @Override
    public ConnectInfoV2 checkConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        InfoResponse infoResponse = connectorApiFactory.getInfoApiClientV2(connectorInfo).getConnectorInfo(connectorInfo);

        ConnectInfoV2 connectInfo = new ConnectInfoV2();
        connectInfo.setConnectorUuid(NullUtil.parseUuidOrNull(connectorInfo.getUuid()));
        connectInfo.setConnector(infoResponse.getConnector());
        connectInfo.setInterfaces(infoResponse.getInterfaces());
        return connectInfo;
    }

    @Override
    public ConnectInfo validateConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        ConnectInfoV2 connectInfo = checkConnection(connectorInfo);
        return validateConnection(connectInfo);
    }

    @Override
    public ConnectInfo validateConnection(ConnectInfo connectInfoV2) throws ConnectorException {
        ConnectInfoV2 connectInfo = (ConnectInfoV2) connectInfoV2;

        // Validate that mandatory interfaces are present in list of interfaces provided by the Connector and also at least one other functional provider
        EnumSet<ConnectorInterface> mandatoryInterfaces = EnumSet.copyOf(List.of(ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS));
        Set<ConnectorInterface> implementedInterfaces = connectInfo.getInterfaces().stream().map(ConnectorInterfaceInfo::getCode).collect(Collectors.toSet());

        if (!implementedInterfaces.containsAll(mandatoryInterfaces)) {
            mandatoryInterfaces.removeAll(implementedInterfaces);
            throw new ValidationException("Connector is missing mandatory interfaces: " + String.join(", ", mandatoryInterfaces.stream().map(ConnectorInterface::getLabel).toList()));
        }

        if (implementedInterfaces.size() == mandatoryInterfaces.size()) {
            throw new ValidationException("Connector is missing any functional interface. At least one functional interface must be implemented in addition to mandatory interfaces.");
        }

        return connectInfo;
    }

    @Override
    public void updateConnectorFunctions(Connector connector, ConnectInfo connectInfo) throws ConnectorException, NotFoundException {
        ConnectInfoV2 connectInfoV2 = (ConnectInfoV2) connectInfo;

        // Get existing interfaces from DB
        Set<ConnectorInterfaceEntity> existingInterfaces = connector.getInterfaces();

        // Build a map of existing interfaces by code+version for quick lookup
        Map<String, ConnectorInterfaceEntity> existingMap = existingInterfaces.stream()
                .collect(Collectors.toMap(
                        e -> e.getInterfaceCode().getCode() + ":" + e.getVersion(),
                        e -> e
                ));

        // Track which interfaces are in the new info
        Set<String> newInterfaceKeys = new HashSet<>();

        // Process interfaces from ConnectInfoV2
        for (ConnectorInterfaceInfo interfaceInfo : connectInfoV2.getInterfaces()) {
            String key = interfaceInfo.getCode().getCode() + ":" + interfaceInfo.getVersion();
            newInterfaceKeys.add(key);

            ConnectorInterfaceEntity existing = existingMap.get(key);
            if (existing != null) {
                // Interface with same code and version exists - update features if changed
                if (!Objects.equals(existing.getFeatures(), interfaceInfo.getFeatures())) {
                    existing.setFeatures(interfaceInfo.getFeatures());
                    connectorInterfaceRepository.save(existing);
                }
                // Skip if nothing changed
            } else {
                // Create new interface entity
                ConnectorInterfaceEntity newInterface = new ConnectorInterfaceEntity();
                newInterface.setConnectorUuid(connector.getUuid());
                newInterface.setInterfaceCode(interfaceInfo.getCode());
                newInterface.setVersion(interfaceInfo.getVersion());
                newInterface.setFeatures(interfaceInfo.getFeatures());
                connectorInterfaceRepository.save(newInterface);
                connector.getInterfaces().add(newInterface);
            }
        }

        // Collect interfaces to remove first, then remove them
        List<ConnectorInterfaceEntity> toRemove = existingInterfaces.stream()
                .filter(existing -> !newInterfaceKeys.contains(existing.getInterfaceCode().getCode() + ":" + existing.getVersion()))
                .toList();

        if (!toRemove.isEmpty()) {
            // Remove interfaces that are no longer present in ConnectInfoV2
            for (ConnectorInterfaceEntity interfaceToRemove : toRemove) {
                connectorInterfaceRepository.delete(interfaceToRemove);
                connector.getInterfaces().remove(interfaceToRemove);
            }
            logger.debug("Removed {} interfaces", toRemove.size());
        }
    }
}
