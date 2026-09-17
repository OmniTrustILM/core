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
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = "proxy.enabled=false")
class ConnectorApiFactoryDiscoveryV2NoProxyITest extends BaseSpringBootTest {

    @Autowired
    private ConnectorApiFactory connectorApiFactory;
    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    void keyManagementV2_usesRestClient_whenMqIsDisabled() {
        // given
        String proxyCode = "key-management-proxy";
        ConnectorDetailDto connector = new ConnectorDetailDto();
        ProxyDto proxy = new ProxyDto();
        proxy.setCode(proxyCode);
        connector.setProxy(proxy);

        // when
        KeySyncApiClient client = connectorApiFactory.getKeyManagementApiClientV2(connector);

        // then
        assertThat(client).isInstanceOf(com.otilm.api.clients.cryptography.v2.KeyApiClient.class);
    }

    @Test
    void proxiedConnectorFallsBackToRestWhenTheMqBeanIsAbsent() {
        Connector connector = new Connector();
        connector.setName("discovery-v2-factory-fallback");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);

        ConnectorDetailDto dto = connector.mapToDetailDto();
        ProxyDto proxy = new ProxyDto();
        proxy.setCode("proxy-1");
        dto.setProxy(proxy);

        DiscoverySyncApiClient client = connectorApiFactory.getDiscoveryApiClientV2(dto);

        assertThat(client).isInstanceOf(com.otilm.api.clients.discovery.v2.DiscoveryApiClient.class);
    }
}
