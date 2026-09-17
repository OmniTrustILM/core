package com.otilm.core.integration.client;

import com.otilm.api.interfaces.client.v2.DiscoverySyncApiClient;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.proxy.ProxyDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/** The test context runs with {@code proxy.enabled=true}, so the MQ bean exists here. */
class ConnectorApiFactoryDiscoveryV2ITest extends BaseSpringBootTest {

    @Autowired
    private ConnectorApiFactory connectorApiFactory;
    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    void directConnectorGetsTheRestClient() {
        DiscoverySyncApiClient client = connectorApiFactory.getDiscoveryApiClientV2(savedConnectorDto(null));

        assertThat(client).isInstanceOf(com.otilm.api.clients.discovery.v2.DiscoveryApiClient.class);
    }

    @Test
    void proxiedConnectorGetsTheMqClient() {
        DiscoverySyncApiClient client = connectorApiFactory.getDiscoveryApiClientV2(savedConnectorDto("proxy-1"));

        assertThat(client).isInstanceOf(com.otilm.api.clients.mq.discovery.v2.DiscoveryApiClient.class);
    }

    @Test
    void keyManagementV2_usesRestClient_forDirectConnector() {
        // given
        ConnectorDetailDto connector = savedConnectorDto(null);

        // when
        KeySyncApiClient client = connectorApiFactory.getKeyManagementApiClientV2(connector);

        // then
        assertThat(client).isInstanceOf(com.otilm.api.clients.cryptography.v2.KeyApiClient.class);
    }

    @Test
    void keyManagementV2_usesMqClient_forProxiedConnector() {
        // given
        String proxyCode = "key-management-proxy";
        ConnectorDetailDto connector = savedConnectorDto(proxyCode);

        // when
        KeySyncApiClient client = connectorApiFactory.getKeyManagementApiClientV2(connector);

        // then
        assertThat(client).isInstanceOf(com.otilm.api.clients.mq.v2.KeyApiClient.class);
    }

    private ConnectorDetailDto savedConnectorDto(String proxyCode) {
        Connector connector = new Connector();
        connector.setName("discovery-v2-factory-" + (proxyCode != null ? proxyCode : "direct"));
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);

        ConnectorDetailDto dto = connector.mapToDetailDto();
        if (proxyCode != null) {
            ProxyDto proxy = new ProxyDto();
            proxy.setCode(proxyCode);
            dto.setProxy(proxy);
        }
        return dto;
    }
}
