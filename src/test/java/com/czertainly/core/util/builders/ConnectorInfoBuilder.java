package com.czertainly.core.util.builders;

import com.otilm.api.model.client.connector.v2.ConnectorInfo;

public class ConnectorInfoBuilder {

    private String id = "ilm.test.connector";
    private String name = "test-connector";
    private String version = "1.0.0";
    private String description = null;

    public static ConnectorInfoBuilder aConnectorInfo() {
        return new ConnectorInfoBuilder();
    }

    public ConnectorInfoBuilder withId(String id) {
        this.id = id;
        return this;
    }

    public ConnectorInfoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ConnectorInfoBuilder withVersion(String version) {
        this.version = version;
        return this;
    }

    public ConnectorInfoBuilder withDescription(String desc) {
        this.description = desc;
        return this;
    }

    public ConnectorInfo build() {
        ConnectorInfo info = new ConnectorInfo();
        info.setId(id);
        info.setName(name);
        info.setVersion(version);
        info.setDescription(description);
        return info;
    }
}
