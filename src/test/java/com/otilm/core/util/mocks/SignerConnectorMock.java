package com.otilm.core.util.mocks;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;

import java.util.List;

/**
 * Mock of a V2 delegated-signer connector — stubs {@code GET /v2/info} advertising
 * {@link ConnectorInterface#SIGNING}. Used exclusively to back delegated signing profiles.
 */
public class SignerConnectorMock extends BaseConnectorMock {

    private SignerConnectorMock() {
        stubV2Info(List.of(
                ConnectorInterface.INFO,
                ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS,
                ConnectorInterface.SIGNING));
    }

    public static SignerConnectorMock start() {
        return new SignerConnectorMock();
    }
}
