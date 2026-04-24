package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeContent;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.MetadataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.error.ErrorCode;
import com.czertainly.api.model.common.error.ProblemDetailExtended;
import com.czertainly.api.model.connector.secrets.SecretContentResponseDto;
import com.czertainly.api.model.connector.secrets.SecretResponseDto;
import com.czertainly.api.model.connector.secrets.SecretType;
import com.czertainly.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.secret.*;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.messaging.jms.listeners.ActionsListener;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.messaging.model.SecretActionData;
import com.czertainly.core.messaging.jms.producers.ActionProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.util.SerializationUtils;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

class SecretServiceTest extends BaseSpringBootTest {

    private static final String TEST_CUSTOM_ATTRIBUTE = "testCustomAttribute";

    private static final int AUTH_SERVICE_MOCK_PORT = 10000;
    @Autowired
    private Secret2SyncVaultProfileRepository secret2SyncVaultProfileRepository;

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:" + AUTH_SERVICE_MOCK_PORT);
    }

    @Autowired
    private SecretService secretService;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private AttributeService attributeService;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ActionsListener actionListener;
    @MockitoBean
    private ActionProducer actionProducer;
    @MockitoBean
    private AuthHelper authHelper;

    private Secret secret;
    private VaultProfile vaultProfile;
    private VaultInstance vaultInstance;
    private WireMockServer mockServer;
    private Connector connector;

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException, NoSuchAlgorithmException, JsonProcessingException {

        // Process message instead of sending it to the queue and set approval status to approved to bypass approval in tests
        Mockito.doAnswer(invocation -> {
                    ActionMessage msg = invocation.getArgument(0);
                    msg.setApprovalStatus(ApprovalStatusEnum.APPROVED);
                    msg.setApprovalUuid(UUID.randomUUID());
                    actionListener.processMessage(msg);
                    return null; // because produceMessage returns void
                }
        ).when(actionProducer).produceMessage(any());
        Mockito.doNothing().when(authHelper).authenticateAsUser(any());

        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
        WireMock.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/secretProvider/secrets/basicAuth/attributes"))
                .willReturn(WireMock.okJson("[]")));
        SecretResponseDto secretResponseDto = new SecretResponseDto();
        secretResponseDto.setName("testSecret");
        secretResponseDto.setVersion("1.2");
        MetadataAttributeV3 metadataAttributeV3 = new MetadataAttributeV3();
        metadataAttributeV3.setName("testAttribute");
        metadataAttributeV3.setUuid(UUID.randomUUID().toString());
        metadataAttributeV3.setContentType(AttributeContentType.STRING);
        metadataAttributeV3.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("label");
        metadataAttributeV3.setProperties(properties);
        secretResponseDto.setMetadata(List.of(metadataAttributeV3));
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretResponseDto))));
        WireMock.stubFor(WireMock.put(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretResponseDto))));
        WireMock.stubFor(WireMock.delete(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.ok()));
        WireMock.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/secretProvider/vaults/attributes"))
                .willReturn(WireMock.okJson("[]")));
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/vaultProfiles/attributes"))
                .willReturn(WireMock.okJson("[]")));
        SecretContentResponseDto secretContentResponseDto = new SecretContentResponseDto();
        BasicAuthSecretContent basicAuthSecretContent = new BasicAuthSecretContent();
        basicAuthSecretContent.setPassword("testPassword");
        basicAuthSecretContent.setUsername("testUsername");
        secretContentResponseDto.setContent(basicAuthSecretContent);
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/secrets/content"))
                .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretContentResponseDto))));

        connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);

        vaultInstance = new VaultInstance();
        vaultInstance.setName("testInstance");
        vaultInstance.setConnector(connector);
        vaultInstanceRepository.save(vaultInstance);

        vaultProfile = new VaultProfile();
        vaultProfile.setName("testProfile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);

        secret = new Secret();
        secret.setName("testSecret");
        secret.setType(com.czertainly.api.model.connector.secrets.SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setEnabled(true);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());


        SecretVersion secretVersion = new SecretVersion();
        secretVersion.setVersion(1);
        secretVersion.setVaultProfile(vaultProfile);
        BasicAuthSecretContent secretContent = new BasicAuthSecretContent();
        secretContent.setPassword("testPassword");
        secretContent.setUsername("testUsername");
        secretVersion.setFingerprint(SecretsUtil.calculateSecretContentFingerprint(secretContent));
        secretVersionRepository.save(secretVersion);

        secret.setLatestVersion(secretVersion);
        secretRepository.save(secret);

        secretVersion.setSecretUuid(secret.getUuid());
        secretVersionRepository.save(secretVersion);

        CustomAttributeCreateRequestDto dto = new CustomAttributeCreateRequestDto();
        dto.setName(TEST_CUSTOM_ATTRIBUTE);
        dto.setLabel("Test Attribute");
        dto.setContentType(AttributeContentType.STRING);
        dto.setResources(List.of(Resource.SECRET));
        attributeService.createCustomAttribute(dto);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testCreateSecret() throws NotFoundException, AttributeException, AlreadyExistException, ConnectorException {
        SecretRequestDto request = new SecretRequestDto();
        request.setName(secret.getName());
        Assertions.assertThrows(AlreadyExistException.class, () -> secretService.createSecret(request, vaultInstance.getSecuredParentUuid(), vaultProfile.getSecuredUuid()));
        request.setName("newSecret");
        Assertions.assertThrows(NotFoundException.class, () -> secretService.createSecret(request, SecuredParentUUID.fromUUID(UUID.randomUUID()), vaultInstance.getSecuredUuid()));
        SecuredUUID securedUUID = SecuredUUID.fromUUID(UUID.randomUUID());
        SecuredParentUUID vaultProfileSecuredParentUuid = vaultProfile.getSecuredParentUuid();
        Assertions.assertThrows(ValidationException.class, () -> secretService.createSecret(request, vaultProfileSecuredParentUuid, securedUUID));

        request.setDescription("Test secret description");
        BasicAuthSecretContent secretContent = new BasicAuthSecretContent();
        secretContent.setPassword("testPassword2");
        secretContent.setUsername("testUsername2");
        request.setSecret(secretContent);
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        request.setCustomAttributes(List.of(attribute));

        SecretDetailDto secretDetailDto = secretService.createSecret(request, vaultProfileSecuredParentUuid, vaultInstance.getSecuredUuid());
        Assertions.assertNotNull(secretDetailDto);
        Assertions.assertEquals(request.getName(), secretDetailDto.getName());
        Assertions.assertNotNull(secretDetailDto.getUuid());
        Assertions.assertEquals(request.getDescription(), secretDetailDto.getDescription());

        Assertions.assertNotNull(secretDetailDto.getCustomAttributes());
        Assertions.assertEquals(1, secretDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), secretDetailDto.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data", ((List<AttributeContent>) secretDetailDto.getCustomAttributes().getFirst().getContent()).getFirst().getData());
        Assertions.assertEquals(1, secretDetailDto.getVersion());

        // Reload secret details since it was created separately
        secretDetailDto = secretService.getSecretDetails(UUID.fromString(secretDetailDto.getUuid()));
        Assertions.assertEquals(SecretType.BASIC_AUTH, secretDetailDto.getType());

        Assertions.assertNotNull(secretDetailDto.getMetadata());
        Assertions.assertEquals(1, secretDetailDto.getMetadata().size());
        Assertions.assertEquals("label", secretDetailDto.getMetadata().getFirst().getItems().getFirst().getLabel());
        Assertions.assertEquals(vaultProfile.getName(), secretDetailDto.getMetadata().getFirst().getItems().getFirst().getSourceObjects().getFirst().getName());
    }

    @Test
    void testSecretOperationFailed() throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException, JsonProcessingException {
        // Remove stubbing to cause failure in secret operations
        mockServer.resetAll();
        Mockito.doNothing().when(actionProducer).produceMessage(any());
        VaultInstance newVaultInstance = new VaultInstance();
        newVaultInstance.setName("newVaultInstance");
        newVaultInstance.setConnector(connector);
        vaultInstanceRepository.save(newVaultInstance);
        VaultProfile newVaultProfileWithNewInstance = new VaultProfile();
        newVaultProfileWithNewInstance.setName("newVaultProfileNewInstance");
        newVaultProfileWithNewInstance.setVaultInstance(newVaultInstance);
        vaultProfileRepository.save(newVaultProfileWithNewInstance);

        SecretRequestDto request = new SecretRequestDto();
        request.setName("newSecret");
        request.setSecret(new BasicAuthSecretContent());
        SecretDetailDto secretDetailDto = secretService.createSecret(request, vaultProfile.getSecuredParentUuid(), vaultInstance.getSecuredUuid());
        ActionMessage actionMessage = new ActionMessage();
        actionMessage.setResourceUuid(UUID.fromString(secretDetailDto.getUuid()));
        actionMessage.setResourceAction(ResourceAction.CREATE);
        actionMessage.setData(SecretActionData.builder()
                .name(request.getName())
                .originalState(SecretState.ACTIVE)
                .updatedSourceVaultProfileUuid(newVaultProfileWithNewInstance.getUuid())
                .encryptedContent(SecretsUtil.encryptAndEncodeSecretString(new ObjectMapper().writeValueAsString(request.getSecret()), SecretEncodingVersion.V1))
                .deleteInVault(Boolean.TRUE)
                .build());
        Assertions.assertThrows(SecretOperationException.class, () -> secretService.processSecretAction(actionMessage, true, true));
        Secret newSecret = secretRepository.findWithAssociationsByUuid(UUID.fromString(secretDetailDto.getUuid())).orElseThrow();
        Assertions.assertEquals(SecretState.FAILED, newSecret.getState());

        SecretUpdateRequestDto updateRequest = new SecretUpdateRequestDto();
        updateRequest.setSecret(new BasicAuthSecretContent());
        SecretState originalState = secret.getState();
        actionMessage.setResourceAction(ResourceAction.UPDATE);
        actionMessage.setResourceUuid(secret.getUuid());
        Assertions.assertThrows(SecretOperationException.class, () -> secretService.processSecretAction(actionMessage, true, true));
        Secret secretReloaded = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(originalState, secretReloaded.getState());

        actionMessage.setResourceAction(ResourceAction.DELETE);
        Assertions.assertThrows(SecretOperationException.class, () -> secretService.processSecretAction(actionMessage, true, true));
        secretReloaded = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(originalState, secretReloaded.getState());

        actionMessage.setResourceAction(ResourceAction.UPDATE_SOURCE_VAULT_PROFILE);
        Assertions.assertThrows(SecretOperationException.class, () -> secretService.processSecretAction(actionMessage, true, true));
        secretReloaded = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(originalState, secretReloaded.getState());

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/secrets/content"))
                .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(new BasicAuthSecretContent()))));
        Assertions.assertThrows(SecretOperationException.class, () -> secretService.processSecretAction(actionMessage, true, true));
        secretReloaded = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(originalState, secretReloaded.getState());
    }

    @Test
    void testUpdateSecret() throws NotFoundException, AttributeException, ConnectorException {
        Assertions.assertThrows(NotFoundException.class, () -> secretService.updateSecret(UUID.randomUUID(), new SecretUpdateRequestDto()));
        addSyncVaultProfile(secret);
        SecretUpdateRequestDto request = new SecretUpdateRequestDto();
        request.setDescription("Test secret new description");
        BasicAuthSecretContent secretContent = new BasicAuthSecretContent();
        secretContent.setPassword("testPassword3");
        secretContent.setUsername("testUsername3");
        request.setSecret(secretContent);
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data2")));
        request.setCustomAttributes(List.of(attribute));
        SecretDetailDto secretDetailDto = secretService.updateSecret(secret.getUuid(), request);
        var served = mockServer.findAll(WireMock.postRequestedFor(WireMock.anyUrl()));
        Assertions.assertEquals(2, served.size());

        Assertions.assertEquals(request.getDescription(), secretDetailDto.getDescription());
        Assertions.assertNotNull(secretDetailDto.getCustomAttributes());
        Assertions.assertEquals(1, secretDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), secretDetailDto.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data2", ((List<AttributeContent>) secretDetailDto.getCustomAttributes().getFirst().getContent()).getFirst().getData());

        secretDetailDto = secretService.getSecretDetails(secret.getUuid());
        Assertions.assertEquals(2, secretDetailDto.getVersion());

        Assertions.assertNotNull(secretDetailDto.getMetadata());
        Assertions.assertEquals(1, secretDetailDto.getMetadata().size());
        Assertions.assertEquals(2, secretDetailDto.getMetadata().getFirst().getItems().getFirst().getSourceObjects().size());

        // Check that the version has not changed with the same content
        secretDetailDto = secretService.updateSecret(secret.getUuid(), request);
        Assertions.assertEquals(2, secretDetailDto.getVersion());

        request.setSecret(null);
        secretDetailDto = secretService.updateSecret(secret.getUuid(), request);
        Assertions.assertEquals(2, secretDetailDto.getVersion());
    }

    private void addSyncVaultProfile(Secret secret) {
        VaultInstance vaultInstance1 = new VaultInstance();
        vaultInstance1.setName("vaultInstance1");
        vaultInstance1.setConnector(connector);
        vaultInstanceRepository.save(vaultInstance1);
        VaultProfile newVaultProfile = new VaultProfile();
        newVaultProfile.setName("newVaultProfile");
        newVaultProfile.setVaultInstance(vaultInstance1);
        vaultProfileRepository.save(newVaultProfile);
        Secret2SyncVaultProfile secret2SyncVaultProfile = new Secret2SyncVaultProfile();
        secret2SyncVaultProfile.setId(new Secret2SyncVaultProfileId(secret.getUuid(), newVaultProfile.getUuid()));
        secret2SyncVaultProfile.setSecret(secret);
        secret2SyncVaultProfile.setVaultProfile(newVaultProfile);
        secret2SyncVaultProfileRepository.save(secret2SyncVaultProfile);
    }

    @Test
    void testDeleteSecret() throws NotFoundException, ConnectorException, AttributeException {
        SecretVersion latestVersion = secret.getLatestVersion();
        secret.getLatestVersion().setSecret(null);
        secretVersionRepository.save(secret.getLatestVersion());
        secretService.deleteSecret(secret.getUuid(), false);
        Assertions.assertThrows(NotFoundException.class, () -> secretService.deleteSecret(secret.getUuid(), false));
        secret.setLatestVersion(latestVersion);
        secretRepository.save(secret);
        addSyncVaultProfile(secret);
        WireMock.stubFor(WireMock.delete(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.jsonResponse(ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_NOT_FOUND, "", null, null), HttpStatus.NOT_FOUND.value())
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        Assertions.assertDoesNotThrow(() -> secretService.deleteSecret(secret.getUuid(), true));
        var served = mockServer.findAll(WireMock.deleteRequestedFor(WireMock.anyUrl()));
        Assertions.assertEquals(2, served.size());
    }

    @Test
    void testEnableSecret() throws NotFoundException {
        secret.setState(SecretState.REJECTED);
        secretRepository.save(secret);
        UUID secretUuid = secret.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> secretService.enableSecret(secretUuid));
        secret.setState(SecretState.ACTIVE);
        secretRepository.save(secret);
        secretService.enableSecret(secretUuid);
        Assertions.assertTrue(secretRepository.findById(secretUuid).orElseThrow().isEnabled());
    }

    @Test
    void testDisableSecret() throws NotFoundException {
        secretService.disableSecret(secret.getUuid());
        Assertions.assertFalse(secretRepository.findById(secret.getUuid()).orElseThrow().isEnabled());
    }

    @Test
    void testGetSecretVersions() throws NotFoundException {
        List<SecretVersionDto> secretVersions = secretService.getSecretVersions(secret.getUuid());
        Assertions.assertEquals(1, secretVersions.size());
        Assertions.assertEquals(1, secretVersions.getFirst().getVersion());
    }

    @Test
    void testAddAndRemoveVaultProfileToSecret() throws NotFoundException, ConnectorException, AttributeException {
        UUID secretUuid = secret.getUuid();
        UUID sourceVaultProfileUuid = vaultProfile.getUuid();
        List<RequestAttribute> createSecretAttributes = List.of();
        Assertions.assertThrows(ValidationException.class, () -> secretService.addVaultProfileToSecret(secretUuid, sourceVaultProfileUuid, createSecretAttributes));

        secret.setState(SecretState.PENDING_APPROVAL);
        secretRepository.save(secret);
        Assertions.assertThrows(ValidationException.class, () -> secretService.addVaultProfileToSecret(secretUuid, sourceVaultProfileUuid, createSecretAttributes));
        secret.setState(SecretState.ACTIVE);
        secretRepository.save(secret);

        VaultProfile newVaultProfile = new VaultProfile();
        newVaultProfile.setName("newVaultProfile");
        newVaultProfile.setVaultInstance(vaultInstance);
        vaultProfileRepository.save(newVaultProfile);

        Secret2SyncVaultProfile secret2SyncVaultProfile = new Secret2SyncVaultProfile();
        secret2SyncVaultProfile.setId(new Secret2SyncVaultProfileId(secretUuid, newVaultProfile.getUuid()));
        secret2SyncVaultProfile.setSecret(secret);
        secret2SyncVaultProfile.setVaultProfile(newVaultProfile);
        secret2SyncVaultProfileRepository.save(secret2SyncVaultProfile);

        UUID newVaultProfileUuid = newVaultProfile.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> secretService.addVaultProfileToSecret(secretUuid, newVaultProfileUuid, createSecretAttributes));

        secret2SyncVaultProfileRepository.delete(secret2SyncVaultProfile);
        secretService.addVaultProfileToSecret(secretUuid, newVaultProfileUuid, createSecretAttributes);

        VaultInstance newVaultInstance = new VaultInstance();
        newVaultInstance.setName("newVaultInstance");
        newVaultInstance.setConnector(connector);
        vaultInstanceRepository.save(newVaultInstance);
        VaultProfile newVaultProfileWithNewInstance = new VaultProfile();
        newVaultProfileWithNewInstance.setName("newVaultProfileNewInstance");
        newVaultProfileWithNewInstance.setVaultInstance(newVaultInstance);
        vaultProfileRepository.save(newVaultProfileWithNewInstance);
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.jsonResponse(ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_ALREADY_EXISTS, "", null, null), HttpStatus.CONFLICT.value())
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        Assertions.assertDoesNotThrow(() -> secretService.addVaultProfileToSecret(secretUuid, newVaultProfileWithNewInstance.getUuid(), createSecretAttributes));

        Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertTrue(reloadedSecret.getSyncVaultProfiles().stream().anyMatch(s -> s.getVaultProfile().getUuid().equals(newVaultProfileUuid)));

        Assertions.assertThrows(ValidationException.class, () -> secretService.removeVaultProfileFromSecret(secretUuid, sourceVaultProfileUuid, false));
        secretService.removeVaultProfileFromSecret(secretUuid, newVaultProfileUuid, false);

        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertFalse(reloadedSecret.getSyncVaultProfiles().contains(secret2SyncVaultProfile));

        // Test removing vault profile with delete in vault set to true
        secretService.removeVaultProfileFromSecret(secretUuid, newVaultProfileWithNewInstance.getUuid(), true);
        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertTrue(reloadedSecret.getSyncVaultProfiles().stream().noneMatch(s -> s.getVaultProfile().getUuid().equals(newVaultProfileWithNewInstance.getUuid())));

    }


    @Test
    void testGetSecretDetails() throws NotFoundException {
        SecretDetailDto secretDetailDto = secretService.getSecretDetails(secret.getUuid());
        Assertions.assertNotNull(secretDetailDto);
        Assertions.assertEquals(secret.getUuid().toString(), secretDetailDto.getUuid());
        Assertions.assertEquals(secret.getName(), secretDetailDto.getName());
        Assertions.assertEquals(secret.getDescription(), secretDetailDto.getDescription());
        Assertions.assertEquals(secret.getType(), secretDetailDto.getType());
        Assertions.assertEquals(secret.getState(), secretDetailDto.getState());
        Assertions.assertEquals(1, secretDetailDto.getVersion());
    }

    @Test
    void updateSourceVaultProfile() throws NotFoundException, ConnectorException, AttributeException {
        SecretUpdateObjectsDto updateObjectsDto = new SecretUpdateObjectsDto();
        updateObjectsDto.setSourceVaultProfileUuid(vaultProfile.getUuid());
        UUID secretUuid = secret.getUuid();
        Assertions.assertDoesNotThrow(() -> secretService.updateSecretObjects(secretUuid, updateObjectsDto));

        VaultProfile newVaultProfile = new VaultProfile();
        newVaultProfile.setName("newVaultProfile");
        newVaultProfile.setVaultInstance(vaultInstance);
        newVaultProfile.setEnabled(true);
        vaultProfileRepository.save(newVaultProfile);

        updateObjectsDto.setSourceVaultProfileUuid(newVaultProfile.getUuid());

        secret.setState(SecretState.REJECTED);
        secretRepository.save(secret);
        Assertions.assertThrows(ValidationException.class, () -> secretService.updateSecretObjects(secretUuid, updateObjectsDto));
        secret.setState(SecretState.ACTIVE);
        secretRepository.save(secret);

        secretService.updateSecretObjects(secretUuid, updateObjectsDto);
        Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertEquals(newVaultProfile.getUuid(), reloadedSecret.getSourceVaultProfileUuid());
        Assertions.assertEquals(2, reloadedSecret.getLatestVersion().getVersion());

        VaultInstance newVaultInstance = new VaultInstance();
        newVaultInstance.setName("newVaultInstance");
        newVaultInstance.setConnector(connector);
        vaultInstanceRepository.save(newVaultInstance);

        VaultProfile newVaultProfile2 = new VaultProfile();
        newVaultProfile2.setName("newVaultProfile2");
        newVaultProfile2.setVaultInstance(newVaultInstance);
        newVaultProfile2.setEnabled(true);
        vaultProfileRepository.save(newVaultProfile2);

        updateObjectsDto.setSourceVaultProfileUuid(newVaultProfile2.getUuid());
        secretService.updateSecretObjects(secretUuid, updateObjectsDto);
        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertEquals(newVaultProfile2.getUuid(), reloadedSecret.getSourceVaultProfileUuid());
        Assertions.assertEquals(3, reloadedSecret.getLatestVersion().getVersion());

        // Set vault profile in sync profiles as source
        updateObjectsDto.setSourceVaultProfileUuid(newVaultProfile.getUuid());
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                .willReturn(WireMock.jsonResponse(ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_ALREADY_EXISTS, "", null, null), HttpStatus.CONFLICT.value())
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        secretService.updateSecretObjects(secretUuid, updateObjectsDto);
        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertEquals(newVaultProfile.getUuid(), reloadedSecret.getSourceVaultProfileUuid());
        Assertions.assertFalse(secret2SyncVaultProfileRepository.findById(new Secret2SyncVaultProfileId(secretUuid, newVaultProfile.getUuid())).isPresent());
    }

    @Test
    void testSetSecretGroups() throws NotFoundException, ConnectorException, AttributeException {
        Group group = new Group();
        group.setName("TestGroup");
        group.setDescription("Test group description");
        group.setEmail("mai@example.com");
        groupRepository.save(group);
        SecretUpdateObjectsDto updateObjectsDto = new SecretUpdateObjectsDto();
        updateObjectsDto.setGroupUuids(Set.of(group.getUuid()));
        secretService.updateSecretObjects(secret.getUuid(), updateObjectsDto);
        Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(1, reloadedSecret.getGroups().size());
        Assertions.assertTrue(reloadedSecret.getGroups().contains(group));
        Assertions.assertDoesNotThrow(() -> secretService.updateSecretObjects(secret.getUuid(), updateObjectsDto));
    }

    @Test
    void testSetSecretOwner() throws NotFoundException, ConnectorException, AttributeException {
        WireMockServer mockServerUpdateUser = new WireMockServer(AUTH_SERVICE_MOCK_PORT);
        mockServerUpdateUser.start();
        WireMock.configureFor("localhost", mockServerUpdateUser.port());
        mockServerUpdateUser.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson("{ \"username\": \"newOwner\"}")
        ));

        SecretUpdateObjectsDto updateObjectsDto = new SecretUpdateObjectsDto();
        updateObjectsDto.setOwnerUuid(String.valueOf(UUID.randomUUID()));
        secretService.updateSecretObjects(secret.getUuid(), updateObjectsDto);
        Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals("newOwner", reloadedSecret.getOwner().getOwnerUsername());
        mockServerUpdateUser.stop();
    }

    @Test
    void testListSecrets() {
        SearchRequestDto searchRequest = new SearchRequestDto();
        searchRequest.setFilters(List.of(
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_NAME.name(), FilterConditionOperator.CONTAINS, secret.getName()),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_TYPE.name(), FilterConditionOperator.EQUALS, (Serializable) List.of(secret.getType().getCode())),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_STATE.name(), FilterConditionOperator.EQUALS, (Serializable) List.of(secret.getState().getCode())),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_ENABLED.name(), FilterConditionOperator.EQUALS, secret.isEnabled()),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_SOURCE_VAULT_PROFILE.name(), FilterConditionOperator.EQUALS, (Serializable) List.of(secret.getSourceVaultProfile().getName())),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_SYNC_VAULT_PROFILE.name(), FilterConditionOperator.NOT_EQUALS, (Serializable) List.of(secret.getSourceVaultProfile().getName()))
        ));
        PaginationResponseDto<SecretDto> secrets = secretService.listSecrets(searchRequest, SecurityFilter.create());
        Assertions.assertEquals(1, secrets.getTotalItems());
        Assertions.assertEquals(secret.getName(), secrets.getItems().getFirst().getName());
    }

    @Test
    void getSecretContent_whenFingerprintCalcThrows_shouldThrowValidationException() {
        try (MockedStatic<SecretsUtil> mocked = mockStatic(SecretsUtil.class)) {
            mocked.when(() -> SecretsUtil.calculateSecretContentFingerprint(any()))
                    .thenThrow(new JsonProcessingException("boom") {
                    });

            // act + assert
            UUID secretUuid = secret.getUuid();
            Assertions.assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
        }
    }

    @Test
    void testGetSecretContentDisabled() {
        secret.setEnabled(false);
        secretRepository.save(secret);
        UUID secretUuid = secret.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
        secret.setEnabled(true);
        secretRepository.save(secret);
        vaultProfile.setEnabled(false);
        vaultProfileRepository.save(vaultProfile);
        Assertions.assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
    }

    @Test
    void testGetSecretContent() {
        secret.setState(SecretState.FAILED);
        secretRepository.save(secret);
        UUID secretUuid = secret.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
    }

    @Test
    void testListResourceObjects() {
        List<NameAndUuidDto> secrets = secretService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, secrets.size());
        Assertions.assertEquals(secret.getName(), secrets.getFirst().getName());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = secretService.getResourceObjectInternal(secret.getUuid());
        Assertions.assertEquals(secret.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(secret.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = secretService.getResourceObjectExternal(secret.getSecuredUuid());
        Assertions.assertEquals(secret.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(secret.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testHandlingRejectedSecret() throws SecretOperationException, ConnectorException, NotFoundException, AttributeException, JsonProcessingException {
        ActionMessage actionMessage = new ActionMessage();
        actionMessage.setResourceUuid(secret.getUuid());
        actionMessage.setResourceAction(ResourceAction.CREATE);
        actionMessage.setData(SecretActionData.builder().originalState(SecretState.ACTIVE).build());
        secretService.processSecretAction(actionMessage, true, false);
        secret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(SecretState.REJECTED, secret.getState());
        actionMessage.setResourceAction(ResourceAction.UPDATE);
        secretService.processSecretAction(actionMessage, true, false);
        secret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(SecretState.ACTIVE, secret.getState());
    }

    @Test
    void testGetSearchableFieldInformation() {
        // Arrange: start an auth-service mock to handle the getUsers() call
        WireMockServer authServiceMock = new WireMockServer(AUTH_SERVICE_MOCK_PORT);
        authServiceMock.start();
        WireMock.configureFor("localhost", authServiceMock.port());
        authServiceMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/auth/users"))
                .willReturn(WireMock.okJson("{ \"data\": [{\"username\": \"testOwner\"}] }")));

        try {
            // Act
            List<SearchFieldDataByGroupDto> result = secretService.getSearchableFieldInformation();

            // Assert – result is present
            Assertions.assertNotNull(result);
            Assertions.assertFalse(result.isEmpty());

            // One PROPERTY group and one CUSTOM group (custom attribute was created in setUp)
            Assertions.assertEquals(1, result.stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY).count());
            Assertions.assertEquals(1, result.stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.CUSTOM).count());

            // Collect all SearchFieldDataDtos from the PROPERTY group
            List<SearchFieldDataDto> propertyFields = result.stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                    .map(SearchFieldDataByGroupDto::getSearchFieldData)
                    .flatMap(List::stream)
                    .toList();

            Assertions.assertEquals(FilterField.getEnumsForResource(Resource.SECRET).size(), propertyFields.size());

            // SECRET_TYPE values contain all SecretType codes
            SearchFieldDataDto secretTypeField = propertyFields.stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_TYPE.name()))
                    .findFirst()
                    .orElseThrow();
            List<String> secretTypeCodes = Arrays.stream(com.czertainly.api.model.connector.secrets.SecretType.values())
                    .map(com.czertainly.api.model.connector.secrets.SecretType::getCode)
                    .toList();
            Assertions.assertTrue(((List<?>) secretTypeField.getValue()).containsAll(secretTypeCodes));

            // SECRET_STATE values contain all SecretState codes
            SearchFieldDataDto secretStateField = propertyFields.stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_STATE.name()))
                    .findFirst()
                    .orElseThrow();
            List<String> secretStateCodes = Arrays.stream(SecretState.values())
                    .map(SecretState::getCode)
                    .toList();
            Assertions.assertTrue(((List<?>) secretStateField.getValue()).containsAll(secretStateCodes));

            // SECRET_SOURCE_VAULT_PROFILE and SECRET_SYNC_VAULT_PROFILE contain the existing vault profile name
            SearchFieldDataDto sourceVaultProfileField = propertyFields.stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_SOURCE_VAULT_PROFILE.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) sourceVaultProfileField.getValue()).contains(vaultProfile.getName()));

            SearchFieldDataDto syncVaultProfileField = propertyFields.stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_SYNC_VAULT_PROFILE.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) syncVaultProfileField.getValue()).contains(vaultProfile.getName()));

            // SECRET_OWNER values contain the stubbed username
            SearchFieldDataDto ownerField = propertyFields.stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_OWNER.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) ownerField.getValue()).contains("testOwner"));

        } finally {
            authServiceMock.stop();
        }
    }

}
