package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;

import java.util.List;

/**
 * Mock of a V2 connector backing delegated-signing profiles. Registration demands one functional interface, so
 * {@code GET /v2/info} carries {@link ConnectorInterface#SIGNATURE_FORMATTING}.
 */
public class SignerConnectorMock extends BaseConnectorMock {

    SignerConnectorMock() {
        stubV2Info(List
                .of(ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS,
                        ConnectorInterface.SIGNATURE_FORMATTING));
    }
}
