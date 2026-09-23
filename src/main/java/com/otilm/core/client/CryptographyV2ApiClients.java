package com.otilm.core.client;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/** Selects REST or MQ v2 operation clients for a connector, like {@link ConnectorApiFactory} does for the others. */
@Component
public class CryptographyV2ApiClients {

    private final ConnectorApiFactory connectorApiFactory;
    private final CryptographicOperationsSyncApiClient restCryptographicOperationsApiClient;
    private final Optional<CryptographicOperationsSyncApiClient> mqCryptographicOperationsApiClient;

    public CryptographyV2ApiClients(ConnectorApiFactory connectorApiFactory,
            @Qualifier("cryptographicOperationsApiClientV2") CryptographicOperationsSyncApiClient restCryptographicOperationsApiClient,
            @Qualifier("mqCryptographicOperationsApiClientV2") Optional<CryptographicOperationsSyncApiClient> mqCryptographicOperationsApiClient) {
        this.connectorApiFactory = connectorApiFactory;
        this.restCryptographicOperationsApiClient = restCryptographicOperationsApiClient;
        this.mqCryptographicOperationsApiClient = mqCryptographicOperationsApiClient;
    }

    public CryptographicOperationsSyncApiClient getCryptographicOperationsApiClient(ApiClientConnectorInfo connector) {
        return connectorApiFactory
                .getClient(connector, restCryptographicOperationsApiClient, mqCryptographicOperationsApiClient);
    }
}
