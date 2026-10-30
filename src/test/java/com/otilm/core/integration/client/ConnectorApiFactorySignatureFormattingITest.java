package com.otilm.core.integration.client;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.interfaces.client.v1.signing.SignatureFormattingSyncApiClient;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.proxy.ProxyStatus;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.ProxyRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectorApiFactorySignatureFormattingITest extends BaseSpringBootTest {

    @Autowired
    private ConnectorApiFactory connectorApiFactory;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ProxyRepository proxyRepository;

    @Test
    void returnsTheRestClientWhenTheConnectorHasNoProxy() {
        // given
        ApiClientConnectorInfo connector = aConnector(null);

        // when
        SignatureFormattingSyncApiClient client = connectorApiFactory.getSignatureFormattingApiClient(connector);

        // then
        assertThat(client).isInstanceOf(com.otilm.api.clients.signing.SignatureFormattingApiClient.class);
    }

    @Test
    void returnsTheMqClientWhenTheConnectorHasAProxy() {
        // given
        ApiClientConnectorInfo connector = aConnector(aProxy());

        // when
        SignatureFormattingSyncApiClient client = connectorApiFactory.getSignatureFormattingApiClient(connector);

        // then
        assertThat(client).isInstanceOf(com.otilm.api.clients.mq.signing.SignatureFormattingApiClient.class);
    }

    @Test
    void returnsTheRestContentSigningClientWhenTheConnectorHasNoProxy() {
        // given
        ApiClientConnectorInfo connector = aConnector(null);

        // when
        ContentSigningFormattingSyncApiClient client = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);

        // then
        assertThat(client)
                .isInstanceOf(com.otilm.api.clients.signing.contentsigning.ContentSigningFormattingApiClient.class);
    }

    @Test
    void returnsTheMqContentSigningClientWhenTheConnectorHasAProxy() {
        // given
        ApiClientConnectorInfo connector = aConnector(aProxy());

        // when
        ContentSigningFormattingSyncApiClient client = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);

        // then
        assertThat(client)
                .isInstanceOf(com.otilm.api.clients.mq.signing.contentsigning.ContentSigningFormattingApiClient.class);
    }

    private ApiClientConnectorInfo aConnector(Proxy proxy) {
        Connector connector = new Connector();
        connector.setName("c");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector.setProxy(proxy);
        connectorRepository.save(connector);
        return connector.mapToDetailDto();
    }

    private Proxy aProxy() {
        Proxy proxy = new Proxy();
        proxy.setName("formattingProxy");
        proxy.setCode("FORMATTING_PROXY");
        proxy.setStatus(ProxyStatus.CONNECTED);
        return proxyRepository.save(proxy);
    }
}
