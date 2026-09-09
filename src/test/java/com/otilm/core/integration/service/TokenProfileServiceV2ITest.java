package com.otilm.core.integration.service;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.DataAttributeV3Builder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class TokenProfileServiceV2ITest extends BaseSpringBootTest {

    @Autowired
    private TokenProfileExternalService tokenProfileService;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity connectorInterface;
    private TokenInstanceReference token;

    @BeforeEach
    void setUp() {
        connectorMock = connectorMockFactory.startCryptographyProviderV2().stubTokenOperations();
        connector = persistV2Connector(connectorMock.getUrl());
        connectorInterface = persistCryptographyInterface(connector);
        token = persistToken("v2-token-profile-owner");
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void createTokenProfile_persistsProfile_forV2Connector() throws Exception {
        // given
        String profileName = "created-v2-profile";
        String description = "created through a v2 connector";
        String attributeName = "create-profile-scope-label";
        String attributeValue = "persisted-create-profile-scope-value";
        persistTokenAttribute(attributeName, attributeValue);
        String expectedScopedRequest = "{\"tokenAttributes\":[{\"name\":\"" + attributeName
                + "\",\"content\":[{\"data\":\"" + attributeValue + "\"}]}]}";
        var request = aTokenProfileRequest().withName(profileName).withDescription(description).build();

        // when
        TokenProfileDetailDto result = tokenProfileService.createTokenProfile(token.getSecuredParentUuid(), request);

        // then
        assertEquals(profileName, result.getName());
        assertEquals(description, result.getDescription());
        TokenProfile persisted = tokenProfileRepository.findByUuid(UUID.fromString(result.getUuid())).orElseThrow();
        assertEquals(token.getUuid(), persisted.getTokenInstanceReferenceUuid());
        connectorMock.verifyScopedTokenProfileAttributesRequestContaining(expectedScopedRequest);
    }

    @Test
    void editTokenProfile_persistsChanges_forV2Connector() throws Exception {
        // given
        String updatedDescription = "updated through a v2 connector";
        String emptyScopedRequest = "{\"tokenAttributes\":[]}";
        TokenProfile profile = persistProfile("edited-v2-profile");
        EditTokenProfileRequestDto request = editRequest(updatedDescription);

        // when
        TokenProfileDetailDto result = tokenProfileService
                .editTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid(), request);

        // then
        assertNotNull(result);
        assertEquals(updatedDescription, result.getDescription());
        TokenProfile persisted = tokenProfileRepository.findByUuid(profile.getUuid()).orElseThrow();
        assertEquals(updatedDescription, persisted.getDescription());
        assertEquals(token.getUuid(), persisted.getTokenInstanceReferenceUuid());
        connectorMock.verifyScopedTokenProfileAttributesRequest(emptyScopedRequest);
    }

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("token-profile-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface(Connector owner) {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(owner);
        value.setConnectorUuid(owner.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS));
        value = connectorInterfaceRepository.save(value);
        owner.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken(String name) {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName(name);
        value.setConnector(connector);
        value.setConnectorInterface(connectorInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.UNKNOWN);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistProfile(String name) {
        TokenProfile value = new TokenProfile();
        value.setName(name);
        value.setTokenInstanceReference(token);
        value.setEnabled(true);
        return tokenProfileRepository.save(value);
    }

    private static EditTokenProfileRequestDto editRequest(String description) {
        EditTokenProfileRequestDto request = new EditTokenProfileRequestDto();
        request.setDescription(description);
        request.setAttributes(List.of());
        request.setCustomAttributes(List.of());
        return request;
    }

    private void persistTokenAttribute(String name, String value) throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        attributeEngine
                .updateDataAttributeDefinitions(connector.getUuid(), null, List
                        .of(DataAttributeV3Builder.aDataAttribute().withUuid(attributeUuid).withName(name).build()));
        RequestAttributeV3 request = new RequestAttributeV3(attributeUuid, name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, token.getUuid())
                        .connector(connector.getUuid())
                        .build(), List.of(request));
    }
}
