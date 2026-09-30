package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

@SpringBootTest
class CryptographicKeyImportServiceV2ITest extends BaseSpringBootTest {

    private static final String IMPORT_LABEL_SCHEMA = "[{\"uuid\":\"" + UUID.randomUUID()
            + "\",\"name\":\"importLabel\",\"type\":\"data\",\"contentType\":\"string\",\"version\":3,"
            + "\"properties\":{\"label\":\"Import label\",\"visible\":true,\"required\":false,\"readOnly\":false,"
            + "\"list\":false,\"multiSelect\":false}}]";

    @Autowired
    private CryptographicKeyImportExternalService importService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private CryptographicKeyController keyController;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private ContextRefreshListener contextRefreshListener;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity cryptographyInterface;
    private TokenInstanceReference token;
    private TokenProfile profile;

    @BeforeEach
    void setUp() throws Exception {
        connectorMock = connectorMockFactory.startCryptographyProviderV2();
        connector = persistV2Connector(connectorMock.getUrl());
        cryptographyInterface = persistCryptographyInterface();
        token = persistToken();
        profile = persistProfile(true);
        connectorMock.stubImportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        connectorMock.stubImportKeyAttributes(IMPORT_LABEL_SCHEMA);
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void listImportKeyAttributes_returnsTheConnectorsSchemaForTheType() throws Exception {
        // when
        List<BaseAttribute> schema = importService
                .listImportKeyAttributes(token.getUuid(), profile.getUuid(), KeyRequestType.KEY_PAIR);

        // then
        assertEquals(List.of("importLabel"), schema.stream().map(BaseAttribute::getName).toList());
        connectorMock.verifyImportKeyAttributesRequestContaining("{\"keyRequestType\":\"keyPair\"}");
    }

    @Test
    void listImportKeyAttributes_refusesATypeTheProfileDoesNotImport() {
        // given
        UUID tokenUuid = token.getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> importService.listImportKeyAttributes(tokenUuid, profileUuid, KeyRequestType.SECRET));

        // then
        assertTrue(refused.getMessage().contains("does not import a secret key"), refused.getMessage());
        connectorMock.verifyImportKeyAttributesRequests(0);
    }

    @Test
    void listImportKeyAttributes_neverAsksAConnectorWithoutKeyImport() {
        // given
        cryptographyInterface.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT));
        connectorInterfaceRepository.save(cryptographyInterface);
        UUID tokenUuid = token.getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        assertThrows(ValidationException.class,
                () -> importService.listImportKeyAttributes(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR));

        // then
        connectorMock.verifyImportableKeyTypesRequests(0);
        connectorMock.verifyImportKeyAttributesRequests(0);
    }

    @Test
    void listImportKeyAttributes_refusesADisabledProfile() {
        // given
        TokenProfile disabled = persistProfile(false);
        UUID tokenUuid = token.getUuid();
        UUID disabledUuid = disabled.getUuid();

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> importService.listImportKeyAttributes(tokenUuid, disabledUuid, KeyRequestType.KEY_PAIR));

        // then
        assertTrue(refused.getMessage().contains("is disabled"), refused.getMessage());
        connectorMock.verifyImportKeyAttributesRequests(0);
    }

    @Test
    void listImportKeyAttributes_refusesAProfileOfAnotherToken() {
        // given
        UUID otherTokenUuid = persistToken().getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        // then
        assertThrows(NotFoundException.class,
                () -> importService.listImportKeyAttributes(otherTokenUuid, profileUuid, KeyRequestType.KEY_PAIR));
    }

    @Test
    void listImportKeyAttributes_refusesWithoutTheImportPermission() {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        UUID tokenUuid = token.getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        assertThrows(AccessDeniedException.class,
                () -> importService.listImportKeyAttributes(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR));

        // then
        connectorMock.verifyImportKeyAttributesRequests(0);
    }

    @ParameterizedTest
    @CsvSource({"TOKEN_PROFILE, DETAIL", "TOKEN, DETAIL", "TOKEN, MEMBERS"})
    void listImportKeyAttributes_refusesWithoutAccessToTheProfileOrItsToken(Resource resource, ResourceAction action) {
        // given
        denyResourceAccess(resource, action);
        UUID tokenUuid = token.getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        assertThrows(AccessDeniedException.class,
                () -> importService.listImportKeyAttributes(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR));

        // then
        connectorMock.verifyImportKeyAttributesRequests(0);
    }

    @Test
    void listImportKeyAttributes_isAuditedAsAnAttributeListingOfTheProfile() throws Exception {
        // given
        auditLogsToTheDatabase();

        // when
        keyController
                .listImportKeyAttributes(token.getUuid().toString(), profile.getUuid().toString(),
                        KeyRequestType.KEY_PAIR);

        // then
        ArgumentCaptor<AuditLogMessage> sent = ArgumentCaptor.forClass(AuditLogMessage.class);
        verify(auditLogsProducer).produceMessage(sent.capture());
        LogRecord auditRecord = sent.getValue().getLogRecord();
        assertEquals(Operation.LIST_ATTRIBUTES, auditRecord.operation());
        assertEquals(Resource.ATTRIBUTE, auditRecord.resource().type());
        assertTrue(auditRecord.resource().objects().stream().anyMatch(object -> "import".equals(object.name())),
                auditRecord.resource().toString());
        assertEquals(Resource.TOKEN_PROFILE, auditRecord.affiliatedResource().type());
        assertEquals(List.of(profile.getUuid()),
                auditRecord.affiliatedResource().objects().stream().map(ResourceObjectIdentity::uuid).toList());
    }

    @Test
    void importKey_isRegisteredOnKeysAtStartup() {
        // when
        ResourceSyncRequestDto keys = contextRefreshListener
                .getResources()
                .stream()
                .filter(resource -> resource.getName().getCode().equals(Resource.CRYPTOGRAPHIC_KEY.getCode()))
                .findFirst()
                .orElseThrow();

        // then
        assertTrue(keys.getActions().contains(ResourceAction.IMPORT_KEY.getCode()), keys.getActions().toString());
    }

    // ---- fixtures ----

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("import-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface() {
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

    private TokenInstanceReference persistToken() {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("import-token-" + UUID.randomUUID());
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setConnectorInterface(cryptographyInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistProfile(boolean enabled) {
        TokenProfile value = new TokenProfile();
        value.setName("import-profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(enabled);
        return tokenProfileRepository.save(value);
    }

    private void auditLogsToTheDatabase() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.DATABASE);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingService.updateLoggingSettings(settings);
    }
}
