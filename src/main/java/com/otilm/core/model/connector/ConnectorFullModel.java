package com.otilm.core.model.connector;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.proxy.ProxyDto;
import com.otilm.core.model.NamedModel;

import java.util.List;

public interface ConnectorFullModel extends NamedModel {
    ConnectorVersion version();

    String url();

    AuthType authType();

    List<ResponseAttribute> authAttributes();

    ConnectorStatus status();

    ProxyDto proxy();

    List<ImmutableConnectorInterface> connectorInterfaces();

    List<ConnectorFunctionGroupModel> functionGroups();
}
