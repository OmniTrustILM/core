package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.model.NamedModel;
import java.util.UUID;

public interface TokenInstanceBasicModel extends NamedModel {
    String tokenInstanceUuid();

    TokenInstanceStatus status();

    String kind();

    UUID connectorUuid();

    String connectorName();

    UUID connectorInterfaceUuid();

    /** Null for a legacy token that has no connector-interface association. */
    ConnectorInterface connectorInterfaceCode();

    String connectorInterfaceVersion();

    long tokenProfileCount();

    default int providerInterfaceVersion() {
        return connectorInterfaceCode() == null ? 1 : 2;
    }
}
