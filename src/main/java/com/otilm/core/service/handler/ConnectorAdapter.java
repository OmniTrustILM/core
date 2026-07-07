package com.otilm.core.service.handler;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.otilm.core.dao.entity.Connector;

public interface ConnectorAdapter {

    ConnectorVersion getVersion();

    ConnectorInfo getInfo(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    HealthInfo checkHealth(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    ConnectInfo checkConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    ConnectInfo validateConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    /**
     * Validates the metadata of an already-fetched connection descriptor. Implementations expect the
     * version-appropriate {@link ConnectInfo} subtype and return the validated descriptor, or throw
     * {@link com.otilm.api.exception.ValidationException} when the connector's interface set is invalid.
     */
    ConnectInfo validateConnection(ConnectInfo connectInfo) throws ConnectorException;

    void updateConnectorFunctions(Connector connector, ConnectInfo connectInfo) throws ConnectorException, NotFoundException;

}
