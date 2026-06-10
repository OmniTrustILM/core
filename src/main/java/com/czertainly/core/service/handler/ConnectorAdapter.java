package com.czertainly.core.service.handler;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.czertainly.core.dao.entity.Connector;

public interface ConnectorAdapter {

    ConnectorVersion getVersion();

    ConnectorInfo getInfo(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    HealthInfo checkHealth(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    ConnectInfo checkConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    ConnectInfo validateConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException;

    ConnectInfo validateConnection(ConnectInfo connectInfo) throws ConnectorException;

    void updateConnectorFunctions(Connector connector, ConnectInfo connectInfo) throws ConnectorException, NotFoundException;

}
