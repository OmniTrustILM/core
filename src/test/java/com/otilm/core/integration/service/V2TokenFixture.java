package com.otilm.core.integration.service;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * A v2 cryptography provider served by WireMock, with a token and an enabled token profile on it, as the tests of key
 * import need them. The provider declares key import; what it imports is left for each test to stub.
 */
@Component
public class V2TokenFixture {

    private static final List<KeyUsage> PROFILE_USAGES = List
            .of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    /**
     * A provider, with the connector, token and profile persisted for it.
     *
     * @param connectorMock the provider, which the test stops
     * @param cryptographyInterface the cryptography interface the connector registered
     * @param token the token on the connector
     * @param profile the token's profile
     */
    public record V2Token(CryptographyProviderV2ConnectorMock connectorMock,
            ConnectorInterfaceEntity cryptographyInterface, TokenInstanceReference token, TokenProfile profile) {
    }

    /**
     * Starts a provider and persists its connector, token and profile.
     *
     * @return the provider and what was persisted for it
     */
    public V2Token start() {
        CryptographyProviderV2ConnectorMock connectorMock = connectorMockFactory.startCryptographyProviderV2();
        Connector connector = persistV2Connector(connectorMock.getUrl());
        ConnectorInterfaceEntity cryptographyInterface = persistCryptographyInterface(connector);
        TokenInstanceReference token = persistToken(connector, cryptographyInterface);
        return new V2Token(connectorMock, cryptographyInterface, token, persistProfile(token));
    }

    /**
     * Makes the provider declare the features in place of the ones it declared.
     *
     * @param v2Token the provider
     * @param features the features it declares from now on
     */
    public void declare(V2Token v2Token, FeatureFlag... features) {
        v2Token.cryptographyInterface().setFeatures(List.of(features));
        connectorInterfaceRepository.save(v2Token.cryptographyInterface());
    }

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("import-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface(Connector connector) {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT));
        value = connectorInterfaceRepository.save(value);
        connector.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken(Connector connector, ConnectorInterfaceEntity cryptographyInterface) {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("import-token-" + UUID.randomUUID());
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setConnectorInterface(cryptographyInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistProfile(TokenInstanceReference token) {
        TokenProfile value = new TokenProfile();
        value.setName("import-profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(true);
        value.setUsage(PROFILE_USAGES);
        return tokenProfileRepository.save(value);
    }
}
