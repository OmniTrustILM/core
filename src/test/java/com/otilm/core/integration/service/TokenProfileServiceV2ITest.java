package com.otilm.core.integration.service;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyTransferCapabilityDto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
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
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.DataAttributeV3Builder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void createTokenProfile_reportsTheKeyTypesTheConnectorExports() throws Exception {
        // given
        declareKeyExport();
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, KeyAlgorithm.MLDSA);
        var request = aTokenProfileRequest().withName("export-capable-profile").build();

        // when
        TokenProfileDetailDto created = tokenProfileService.createTokenProfile(token.getSecuredParentUuid(), request);

        // then
        KeyTransferCapabilityDto keyTransfer = created.getKeyTransfer();
        assertTrue(keyTransfer.isExportAvailable());
        assertEquals(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA, KeyAlgorithm.MLDSA)),
                keyTransfer.getExportableKeyTypes());
        assertFalse(keyTransfer.isImportAvailable());
    }

    @Test
    void getTokenProfile_reportsTheCachedKeyTypesWithoutAskingTheConnector() throws Exception {
        // given
        declareKeyExport();
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        TokenProfileDetailDto created = tokenProfileService
                .createTokenProfile(token.getSecuredParentUuid(),
                        aTokenProfileRequest().withName("cached-capability-profile").build());

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), SecuredUUID.fromString(created.getUuid()));

        // then
        assertEquals(created.getKeyTransfer(), read.getKeyTransfer());
        connectorMock.verifyExportableKeyTypesRequests(1);
    }

    @Test
    void createTokenProfile_doesNotAskAConnectorThatCannotExport() throws Exception {
        // given
        var request = aTokenProfileRequest().withName("export-incapable-profile").build();

        // when
        TokenProfileDetailDto created = tokenProfileService.createTokenProfile(token.getSecuredParentUuid(), request);

        // then
        assertFalse(created.getKeyTransfer().isExportAvailable());
        assertTrue(created.getKeyTransfer().getExportableKeyTypes().isEmpty());
        connectorMock.verifyExportableKeyTypesRequests(0);
    }

    @Test
    void createTokenProfile_succeedsWhenTheConnectorCannotSayWhatItExports() throws Exception {
        // given
        declareKeyExport();
        connectorMock.stubExportableKeyTypesFailing();
        var request = aTokenProfileRequest().withName("capability-unknown-profile").build();

        // when
        TokenProfileDetailDto created = tokenProfileService.createTokenProfile(token.getSecuredParentUuid(), request);

        // then
        assertFalse(created.getKeyTransfer().isExportAvailable());
        assertNull(recordedAnswer(UUID.fromString(created.getUuid())));
    }

    @Test
    void getTokenProfile_learnsTheAnswerOnceTheConnectorAnswersAgain() throws Exception {
        // given
        declareKeyExport();
        connectorMock.stubExportableKeyTypesFailing();
        TokenProfileDetailDto created = tokenProfileService
                .createTokenProfile(token.getSecuredParentUuid(),
                        aTokenProfileRequest().withName("recovering-capability-profile").build());
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), SecuredUUID.fromString(created.getUuid()));

        // then
        assertTrue(read.getKeyTransfer().isExportAvailable());
    }

    @Test
    void getTokenProfile_learnsWhatAProfileWithoutAnAnswerExports() throws Exception {
        // given
        declareKeyExport();
        TokenProfile preExisting = persistProfile("pre-existing-profile");
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.MLDSA);

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), preExisting.getSecuredUuid());

        // then
        assertEquals(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.MLDSA)),
                read.getKeyTransfer().getExportableKeyTypes());
    }

    @Test
    void getTokenProfile_learnsTheAnswerOnceTheConnectorDeclaresExport() throws Exception {
        // given
        TokenProfile profile = persistProfile("later-exporting-profile");
        tokenProfileService.getTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid());
        declareKeyExport();
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA);

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // then
        assertTrue(read.getKeyTransfer().isExportAvailable());
        connectorMock.verifyExportableKeyTypesRequests(1);
    }

    @Test
    void getTokenProfile_doesNotAskAgainWhenTheConnectorExportsNothing() throws Exception {
        // given
        declareKeyExport();
        TokenProfile profile = persistProfile("non-exporting-profile");
        connectorMock.stubNoExportableKeyTypes();
        tokenProfileService.getTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // then
        assertFalse(read.getKeyTransfer().isExportAvailable());
        connectorMock.verifyExportableKeyTypesRequests(1);
    }

    @Test
    void editTokenProfile_refreshesTheExportableKeyTypes() throws Exception {
        // given
        declareKeyExport();
        TokenProfile profile = persistProfile("refreshed-capability-profile");
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA);

        // when
        TokenProfileDetailDto edited = tokenProfileService
                .editTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid(), editRequest("refreshed"));

        // then
        assertEquals(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.ECDSA)),
                edited.getKeyTransfer().getExportableKeyTypes());
    }

    @Test
    void editTokenProfile_dropsTheAnswerGivenBeforeTheEditWhenTheConnectorCannotAnswer() throws Exception {
        // given
        declareKeyExport();
        TokenProfile profile = persistProfile("edited-while-connector-down-profile");
        profile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
        tokenProfileRepository.saveAndFlush(profile);
        connectorMock.stubExportableKeyTypesFailing();

        // when
        TokenProfileDetailDto edited = tokenProfileService
                .editTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid(), editRequest("edited"));

        // then
        assertFalse(edited.getKeyTransfer().isExportAvailable());
        assertNull(recordedAnswer(profile.getUuid()));
    }

    @Test
    void updateKeyUsages_refreshesCachedExportableKeyTypes() throws Exception {
        // given
        declareKeyExport();
        TokenProfile profile = persistProfile("usage-scoped-capability-profile");
        profile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.ECDSA))));
        tokenProfileRepository.saveAndFlush(profile);
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        tokenProfileService
                .updateKeyUsages(token.getSecuredParentUuid(), profile.getSecuredUuid(), List.of(KeyUsage.ENCRYPT));

        // when
        TokenProfileDetailDto read = tokenProfileService
                .getTokenProfile(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // then
        connectorMock.verifyExportableKeyTypesRequests(1);
        assertEquals(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)),
                read.getKeyTransfer().getExportableKeyTypes());
    }

    @Test
    void updateKeyUsages_dropsTheAnswerOfEveryProfileUpdatedTogether() {
        // given
        TokenProfile first = persistProfile("first-bulk-usage-profile");
        TokenProfile second = persistProfile("second-bulk-usage-profile");
        for (TokenProfile profile : List.of(first, second)) {
            profile
                    .setExportableKeyTypes(
                            List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
            tokenProfileRepository.saveAndFlush(profile);
        }

        // when
        tokenProfileService
                .updateKeyUsages(List.of(first.getSecuredUuid(), second.getSecuredUuid()), List.of(KeyUsage.SIGN));

        // then
        assertNull(recordedAnswer(first.getUuid()));
        assertNull(recordedAnswer(second.getUuid()));
    }

    @Test
    void listSupportedKeyRequestTypes_sendsPersistedTokenAndProfileAttributes() throws Exception {
        // given
        TokenProfile profile = persistProfile("request-types-profile");
        String tokenAttributeName = "token-slot";
        String tokenAttributeValue = "slot-7";
        String profileAttributeName = "profile-policy";
        String profileAttributeValue = "signing";
        persistTokenAttribute(tokenAttributeName, tokenAttributeValue);
        persistAttribute(Resource.TOKEN_PROFILE, profile.getUuid(), profileAttributeName, profileAttributeValue);
        connectorMock.stubKeyRequestTypes("[\"keyPair\"]");
        String expectedRequest = "{\"tokenAttributes\":[{\"name\":\"token-slot\",\"content\":[{\"data\":\"slot-7\"}]}],"
                + "\"tokenProfileAttributes\":[{\"name\":\"profile-policy\",\"content\":[{\"data\":\"signing\"}]}]}";

        // when
        List<KeyRequestType> types = tokenProfileService
                .listSupportedKeyRequestTypes(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // then
        assertEquals(List.of(KeyRequestType.KEY_PAIR), types);
        connectorMock.verifyScopedKeyRequestTypesRequestContaining(expectedRequest);
    }

    @Test
    void listSupportedKeyRequestTypes_rejectsUnauthorizedProfile() {
        // given
        TokenProfile profile = persistProfile("denied-request-types-profile");
        denyResourceAccess(Resource.TOKEN_PROFILE, ResourceAction.MEMBERS);

        // when
        Executable listTypes = () -> tokenProfileService
                .listSupportedKeyRequestTypes(token.getSecuredParentUuid(), profile.getSecuredUuid());

        // then
        assertThrows(AccessDeniedException.class, listTypes);
    }

    private List<TransferableKeyType> recordedAnswer(UUID profileUuid) {
        return tokenProfileRepository.findByUuid(profileUuid).orElseThrow().getExportableKeyTypes();
    }

    private void declareKeyExport() {
        connectorInterface.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT));
        connectorInterfaceRepository.save(connectorInterface);
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
        persistAttribute(Resource.TOKEN, token.getUuid(), name, value);
    }

    private void persistAttribute(Resource resource, UUID objectUuid, String name, String value) throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        attributeEngine
                .updateDataAttributeDefinitions(connector.getUuid(), null, List
                        .of(DataAttributeV3Builder.aDataAttribute().withUuid(attributeUuid).withName(name).build()));
        RequestAttributeV3 request = new RequestAttributeV3(attributeUuid, name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(resource, objectUuid).connector(connector.getUuid()).build(),
                        List.of(request));
    }
}
