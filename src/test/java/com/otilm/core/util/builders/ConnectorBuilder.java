package com.otilm.core.util.builders;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.FunctionGroup;
import java.util.UUID;

/** Builds connector entities and their associations for repository integration tests. */
public final class ConnectorBuilder {

    private String connectorName = "provider-v2";
    private String connectorUrl = "http://provider-v2.test";
    private ConnectorVersion connectorVersion = ConnectorVersion.V2;
    private ConnectorStatus connectorStatus = ConnectorStatus.CONNECTED;
    private String interfaceVersion = "v2";
    private ConnectorInterface interfaceCode = ConnectorInterface.CRYPTOGRAPHY;
    private FunctionGroupCode functionGroupCode = FunctionGroupCode.CRYPTOGRAPHY_PROVIDER;
    private UUID connectorUuid = UUID.randomUUID();
    private UUID functionGroupUuid = UUID.randomUUID();

    public static ConnectorBuilder aConnector() {
        return new ConnectorBuilder();
    }

    public ConnectorBuilder withName(String name) {
        this.connectorName = name;
        return this;
    }

    public ConnectorBuilder withUrl(String url) {
        this.connectorUrl = url;
        return this;
    }

    public ConnectorBuilder withVersion(ConnectorVersion version) {
        this.connectorVersion = version;
        return this;
    }

    public ConnectorBuilder withGeneratedUuid() {
        this.connectorUuid = null;
        return this;
    }

    public ConnectorBuilder withInterfaceCode(ConnectorInterface code) {
        this.interfaceCode = code;
        return this;
    }

    public ConnectorBuilder withFunctionGroupCode(FunctionGroupCode code) {
        this.functionGroupCode = code;
        return this;
    }

    public Connector build() {
        Connector connector = new Connector();
        connector.setUuid(connectorUuid);
        connector.setName(connectorName);
        connector.setUrl(connectorUrl);
        connector.setVersion(connectorVersion);
        connector.setStatus(connectorStatus);
        return connector;
    }

    public Fixture buildFixture() {
        Connector connector = build();

        ConnectorInterfaceEntity connectorInterface = new ConnectorInterfaceEntity();
        connectorInterface.setConnector(connector);
        connectorInterface.setConnectorUuid(connector.getUuid());
        connectorInterface.setInterfaceCode(interfaceCode);
        connectorInterface.setVersion(interfaceVersion);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setUuid(functionGroupUuid);
        functionGroup.setName("Cryptography provider");
        functionGroup.setCode(functionGroupCode);

        Connector2FunctionGroup relation = new Connector2FunctionGroup();
        relation.setConnector(connector);
        relation.setFunctionGroup(functionGroup);
        return new Fixture(connector, connectorInterface, functionGroup, relation);
    }

    public record Fixture(Connector connector, ConnectorInterfaceEntity connectorInterface, FunctionGroup functionGroup,
            Connector2FunctionGroup relation) {
    }
}
