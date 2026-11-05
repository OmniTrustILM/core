package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SecretOperationException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.secrets.SecretContentResponseDto;
import com.otilm.api.model.connector.secrets.SecretResponseDto;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.secret.SecretDetailDto;
import com.otilm.api.model.core.secret.SecretDto;
import com.otilm.api.model.core.secret.SecretRequestDto;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.api.model.core.secret.SecretUpdateObjectsDto;
import com.otilm.api.model.core.secret.SecretUpdateRequestDto;
import com.otilm.api.model.core.secret.SecretVersionDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.Secret2SyncVaultProfile;
import com.otilm.core.dao.entity.Secret2SyncVaultProfileId;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.Secret2SyncVaultProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.SecretContentUpdatedEvent;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.SecretActionData;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import com.otilm.core.util.WireMockPorts;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

@RecordApplicationEvents
class SecretServiceITest extends BaseSpringBootTest {

    private static final String TEST_CUSTOM_ATTRIBUTE = "testCustomAttribute";

    @Autowired
    private Secret2SyncVaultProfileRepository secret2SyncVaultProfileRepository;

    @Autowired
    private ApplicationEvents applicationEvents;
    @Autowired
    private SecretExternalService secretService;

    @Autowired
    private SecretInternalService secretInternalService;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ActionsListener actionListener;
    @Autowired
    private PlatformTransactionManager transactionManager;
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

        // REQUIRES_NEW so the handler runs in its own transaction like the real broker: at afterCommit the producing
        // transaction has already committed, so an inline handler would join it and its writes would be discarded.
        final TransactionTemplate listenerTransaction = new TransactionTemplate(transactionManager);
        listenerTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        Mockito.doAnswer(invocation -> {
            ActionMessage msg = invocation.getArgument(0);
            msg.setApprovalStatus(ApprovalStatusEnum.APPROVED);
            msg.setApprovalUuid(UUID.randomUUID());
            listenerTransaction.executeWithoutResult(status -> {
                try {
                    actionListener.processMessage(msg);
                } catch (MessageHandlingException e) {
                    throw new IllegalStateException(e);
                }
            });
            return null; // because produceMessage returns void
        }).when(actionProducer).produceMessage(any());
        Mockito.doNothing().when(authHelper).authenticateAsUser(any());

        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();

        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/secretProvider/secrets/basicAuth/attributes"))
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
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretResponseDto))));
        WireMock
                .stubFor(WireMock
                        .put(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretResponseDto))));
        WireMock
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock.ok()));
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/secretProvider/vaults/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/vaultProfiles/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        SecretContentResponseDto secretContentResponseDto = new SecretContentResponseDto();
        BasicAuthSecretContent basicAuthSecretContent = new BasicAuthSecretContent();
        basicAuthSecretContent.setPassword("testPassword");
        basicAuthSecretContent.setUsername("testUsername");
        secretContentResponseDto.setContent(basicAuthSecretContent);
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets/content"))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(secretContentResponseDto))));

        connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl(LoopbackWireMock.url(mockServer));
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
        secret.setType(com.otilm.api.model.connector.secrets.SecretType.BASIC_AUTH);
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
    void refusesSecretCreation_whenTheNameIsTaken() {
        // given
        String takenName = secret.getName();
        SecuredParentUUID vaultUuid = vaultInstance.getSecuredParentUuid();
        UUID vaultProfileUuid = vaultProfile.getUuid();
        var request = new SecretRequestDto();
        request.setName(takenName);

        // when
        ThrowingCallable createSecret = () -> secretService.createSecret(request, vaultUuid, vaultProfileUuid);

        // then
        assertThatThrownBy(createSecret).isInstanceOf(AlreadyExistException.class);
    }

    @Test
    void refusesSecretCreation_whenTheVaultProfileDoesNotExist() {
        // given
        SecuredParentUUID vaultUuid = vaultInstance.getSecuredParentUuid();
        UUID missingVaultProfileUuid = UUID.randomUUID();
        var request = new SecretRequestDto();
        request.setName("newSecret");

        // when
        ThrowingCallable createSecret = () -> secretService.createSecret(request, vaultUuid, missingVaultProfileUuid);

        // then
        assertThatThrownBy(createSecret).isInstanceOf(NotFoundException.class);
        assertThat(secretRepository.existsByName(request.getName())).isFalse();
    }

    @Test
    void refusesSecretCreation_whenTheVaultProfileBelongsToAnotherVault() {
        // given
        SecuredParentUUID otherVaultUuid = SecuredParentUUID.fromUUID(UUID.randomUUID());
        UUID vaultProfileUuid = vaultProfile.getUuid();
        var request = new SecretRequestDto();
        request.setName("newSecret");

        // when
        ThrowingCallable createSecret = () -> secretService.createSecret(request, otherVaultUuid, vaultProfileUuid);

        // then
        assertThatThrownBy(createSecret).isInstanceOf(ValidationException.class);
        assertThat(secretRepository.existsByName(request.getName())).isFalse();
    }

    @Test
    void createsTheSecret_whenTheRequestIsValid() throws Exception {
        // given
        var secretContent = new BasicAuthSecretContent();
        secretContent.setPassword("testPassword2");
        secretContent.setUsername("testUsername2");
        var attribute = aCustomAttribute().withName(TEST_CUSTOM_ATTRIBUTE).withStringContent("data").build();
        var request = new SecretRequestDto();
        request.setName("newSecret");
        request.setDescription("Test secret description");
        request.setSecret(secretContent);
        request.setCustomAttributes(List.of(attribute));

        // when
        SecretDetailDto created = secretService
                .createSecret(request, vaultInstance.getSecuredParentUuid(), vaultProfile.getUuid());

        // then
        assertThat(created).isNotNull();
        assertThat(created.getName()).isEqualTo(request.getName());
        assertThat(created.getUuid()).isNotNull();
        assertThat(created.getDescription()).isEqualTo(request.getDescription());
        assertThat(created.getCustomAttributes()).hasSize(1);
        assertThat(created.getCustomAttributes().getFirst().getName()).isEqualTo(attribute.getName());
        Object attributeData = ((List<AttributeContent>) created.getCustomAttributes().getFirst().getContent())
                .getFirst()
                .getData();
        assertThat(attributeData).isEqualTo("data");
        assertThat(created.getVersion()).isEqualTo(1);
        SecretDetailDto stored = secretService.getSecretDetails(UUID.fromString(created.getUuid()));
        assertThat(stored.getType()).isEqualTo(SecretType.BASIC_AUTH);
        assertThat(stored.getMetadata()).hasSize(1);
        assertThat(stored.getMetadata().getFirst().getItems().getFirst().getLabel()).isEqualTo("label");
        assertThat(stored.getMetadata().getFirst().getItems().getFirst().getSourceObjects().getFirst().getName())
                .isEqualTo(vaultProfile.getName());
    }

    @Test
    void marksTheSecretFailed_whenItsApprovedCreationFailsInTheVault() throws Exception {
        // given
        mockServer.resetAll();
        Mockito.doNothing().when(actionProducer).produceMessage(any());
        var request = new SecretRequestDto();
        request.setName("newSecret");
        request.setSecret(new BasicAuthSecretContent());
        SecretDetailDto created = secretService
                .createSecret(request, vaultInstance.getSecuredParentUuid(), vaultProfile.getUuid());
        UUID createdUuid = UUID.fromString(created.getUuid());
        ActionMessage creation = new ActionMessage();
        creation.setResourceUuid(createdUuid);
        creation.setResourceAction(ResourceAction.CREATE);
        creation
                .setData(SecretActionData
                        .builder()
                        .name(request.getName())
                        .encryptedContent(encryptEmptyBasicAuthContent())
                        .build());

        // when
        ThrowingCallable processSecretAction = () -> secretInternalService.processSecretAction(creation, true, true);

        // then
        assertThatThrownBy(processSecretAction).isInstanceOf(SecretOperationException.class);
        Secret failed = secretRepository.findWithAssociationsByUuid(createdUuid).orElseThrow();
        assertThat(failed.getState()).isEqualTo(SecretState.FAILED);
    }

    @ParameterizedTest
    @CsvSource({
            "UPDATE, Failed to update secret",
            "DELETE, Failed to delete secret",
            "UPDATE_SOURCE_VAULT_PROFILE, Could not retrieve secret content"})
    void keepsTheSecretState_whenItsApprovedActionFailsInTheVault(ResourceAction action, String failure)
            throws Exception {
        // given
        mockServer.resetAll();
        SecretState originalState = secret.getState();
        ActionMessage message = secretAction(action, buildActionData(persistVaultProfileOnAnotherVault()));

        // when
        ThrowingCallable processSecretAction = () -> secretInternalService.processSecretAction(message, true, true);

        // then
        assertThatThrownBy(processSecretAction)
                .isInstanceOf(SecretOperationException.class)
                .hasMessageContaining(failure);
        Secret unchanged = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        assertThat(unchanged.getState()).isEqualTo(originalState);
    }

    @Test
    void keepsTheSecretState_whenTheNewSourceVaultFailsToStoreIt() throws Exception {
        // given
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock
                                .jsonResponse(
                                        ProblemDetailExtended
                                                .fromErrorCode(ErrorCode.INTERNAL_SERVER_ERROR, "", null, null),
                                        HttpStatus.INTERNAL_SERVER_ERROR.value())
                                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        SecretState originalState = secret.getState();
        ActionMessage move = secretAction(ResourceAction.UPDATE_SOURCE_VAULT_PROFILE,
                buildActionData(persistVaultProfileOnAnotherVault()));

        // when
        ThrowingCallable processSecretAction = () -> secretInternalService.processSecretAction(move, true, true);

        // then
        assertThatThrownBy(processSecretAction)
                .isInstanceOf(SecretOperationException.class)
                .hasMessageContaining("Failed to create secret in vault");
        Secret unchanged = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        assertThat(unchanged.getState()).isEqualTo(originalState);
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching("/v1/secretProvider/secrets")));
    }

    @Test
    void refusesSecretCreation_whenVaultDetailIsDenied() {
        // given
        denyResourceAccess(Resource.VAULT, ResourceAction.DETAIL, vaultInstance.getUuid());
        SecuredParentUUID vaultUuid = vaultInstance.getSecuredParentUuid();
        UUID vaultProfileUuid = vaultProfile.getUuid();
        var request = new SecretRequestDto();
        request.setName("refusedSecret");
        request.setSecret(new BasicAuthSecretContent());

        // when
        ThrowingCallable createSecret = () -> secretService.createSecret(request, vaultUuid, vaultProfileUuid);

        // then
        assertThatThrownBy(createSecret).isInstanceOf(AccessDeniedException.class);
        assertThat(secretRepository.existsByName(request.getName())).isFalse();
    }

    @ParameterizedTest
    @CsvSource({"CREATE, CREATE", "UPDATE, UPDATE", "UPDATE_SOURCE_VAULT_PROFILE, UPDATE", "DELETE, DELETE"})
    void refusesTheActionWithoutApproval_whenItsPermissionIsDenied(ResourceAction action,
            ResourceAction requiredPermission) throws Exception {
        // given
        denyResourceAccess(Resource.SECRET, requiredPermission);
        ActionMessage message = secretAction(action,
                SecretActionData
                        .builder()
                        .name(secret.getName())
                        .originalState(secret.getState())
                        .updatedSourceVaultProfileUuid(vaultProfile.getUuid())
                        .encryptedContent(encryptEmptyBasicAuthContent())
                        .deleteInVault(Boolean.FALSE)
                        .build());

        // when
        ThrowingCallable processSecretAction = () -> secretInternalService.processSecretAction(message, false, false);

        // then
        assertThatThrownBy(processSecretAction).isInstanceOf(AccessDeniedException.class);
        Secret unchanged = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        assertThat(unchanged.getState()).isEqualTo(secret.getState());
        assertThat(unchanged.getSourceVaultProfileUuid()).isEqualTo(vaultProfile.getUuid());
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    @Test
    void refusesTheCreationWithoutApproval_whenVaultDetailIsDenied() throws Exception {
        // given
        denyResourceAccess(Resource.VAULT, ResourceAction.DETAIL, vaultInstance.getUuid());
        ActionMessage creation = secretAction(ResourceAction.CREATE,
                SecretActionData
                        .builder()
                        .name(secret.getName())
                        .attributes(List.of())
                        .encryptedContent(encryptEmptyBasicAuthContent())
                        .build());

        // when
        ThrowingCallable processSecretAction = () -> secretInternalService.processSecretAction(creation, false, false);

        // then
        assertThatThrownBy(processSecretAction).isInstanceOf(AccessDeniedException.class);
        Secret unchanged = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        assertThat(unchanged.getState()).isEqualTo(secret.getState());
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    @Test
    void createsTheSecret_whenItsActionRunsWithoutApproval() throws Exception {
        // given
        Mockito.doNothing().when(actionProducer).produceMessage(any());
        var request = new SecretRequestDto();
        request.setName("unapprovedSecret");
        request.setSecret(new BasicAuthSecretContent());
        SecretDetailDto created = secretService
                .createSecret(request, vaultInstance.getSecuredParentUuid(), vaultProfile.getUuid());
        UUID createdUuid = UUID.fromString(created.getUuid());
        ActionMessage creation = new ActionMessage();
        creation.setResourceUuid(createdUuid);
        creation.setResourceAction(ResourceAction.CREATE);
        creation
                .setData(SecretActionData
                        .builder()
                        .name(request.getName())
                        .attributes(List.of())
                        .encryptedContent(encryptEmptyBasicAuthContent())
                        .build());

        // when
        secretInternalService.processSecretAction(creation, false, false);

        // then
        Secret createdSecret = secretRepository.findWithAssociationsByUuid(createdUuid).orElseThrow();
        assertThat(createdSecret.getState()).isEqualTo(SecretState.ACTIVE);
    }

    @Test
    void testUpdateSecret() throws NotFoundException, AttributeException, ConnectorException {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> secretService.updateSecret(UUID.randomUUID(), new SecretUpdateRequestDto()));
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
        Assertions
                .assertEquals("data2",
                        ((List<AttributeContent>) secretDetailDto.getCustomAttributes().getFirst().getContent())
                                .getFirst()
                                .getData());

        secretDetailDto = secretService.getSecretDetails(secret.getUuid());
        Assertions.assertEquals(2, secretDetailDto.getVersion());

        Assertions.assertNotNull(secretDetailDto.getMetadata());
        Assertions.assertEquals(1, secretDetailDto.getMetadata().size());
        Assertions
                .assertEquals(2,
                        secretDetailDto.getMetadata().getFirst().getItems().getFirst().getSourceObjects().size());

        // Check that the version has not changed with the same content
        secretDetailDto = secretService.updateSecret(secret.getUuid(), request);
        Assertions.assertEquals(2, secretDetailDto.getVersion());

        request.setSecret(null);
        secretDetailDto = secretService.updateSecret(secret.getUuid(), request);
        Assertions.assertEquals(2, secretDetailDto.getVersion());
    }

    @Test
    void updateSecret_publishesSecretContentUpdatedEvent_whenContentChanges()
            throws NotFoundException, AttributeException, ConnectorException {
        // given — an update whose secret content differs from the current version (a password rotation)
        SecretUpdateRequestDto rotate = new SecretUpdateRequestDto();
        BasicAuthSecretContent rotatedContent = new BasicAuthSecretContent();
        rotatedContent.setUsername("testUsername");
        rotatedContent.setPassword("rotated-password");
        rotate.setSecret(rotatedContent);

        // when — the content actually changes (the ActionProducer shim runs the action synchronously)
        secretService.updateSecret(secret.getUuid(), rotate);

        // then — exactly one SecretContentUpdatedEvent is published for this secret
        assertThat(applicationEvents.stream(SecretContentUpdatedEvent.class).map(SecretContentUpdatedEvent::secretUuid))
                .containsExactly(secret.getUuid());

        // and — an update that does not touch the secret content publishes no further event
        SecretUpdateRequestDto noContentChange = new SecretUpdateRequestDto();
        noContentChange.setDescription("description only");
        secretService.updateSecret(secret.getUuid(), noContentChange);

        assertThat(applicationEvents.stream(SecretContentUpdatedEvent.class)).hasSize(1);
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
        WireMock
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock
                                .jsonResponse(
                                        ProblemDetailExtended
                                                .fromErrorCode(ErrorCode.RESOURCE_NOT_FOUND, "", null, null),
                                        HttpStatus.NOT_FOUND.value())
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
        Assertions
                .assertThrows(ValidationException.class, () -> secretService
                        .addVaultProfileToSecret(secretUuid, sourceVaultProfileUuid, createSecretAttributes));

        secret.setState(SecretState.PENDING_APPROVAL);
        secretRepository.save(secret);
        Assertions
                .assertThrows(ValidationException.class, () -> secretService
                        .addVaultProfileToSecret(secretUuid, sourceVaultProfileUuid, createSecretAttributes));
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
        Assertions
                .assertThrows(ValidationException.class, () -> secretService
                        .addVaultProfileToSecret(secretUuid, newVaultProfileUuid, createSecretAttributes));

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
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock
                                .jsonResponse(
                                        ProblemDetailExtended
                                                .fromErrorCode(ErrorCode.RESOURCE_ALREADY_EXISTS, "", null, null),
                                        HttpStatus.CONFLICT.value())
                                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        Assertions
                .assertDoesNotThrow(() -> secretService
                        .addVaultProfileToSecret(secretUuid, newVaultProfileWithNewInstance.getUuid(),
                                createSecretAttributes));

        Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions
                .assertTrue(reloadedSecret
                        .getSyncVaultProfiles()
                        .stream()
                        .anyMatch(s -> s.getVaultProfile().getUuid().equals(newVaultProfileUuid)));

        Assertions
                .assertThrows(ValidationException.class,
                        () -> secretService.removeVaultProfileFromSecret(secretUuid, sourceVaultProfileUuid, false));
        secretService.removeVaultProfileFromSecret(secretUuid, newVaultProfileUuid, false);

        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertFalse(reloadedSecret.getSyncVaultProfiles().contains(secret2SyncVaultProfile));

        // Test removing vault profile with delete in vault set to true
        secretService.removeVaultProfileFromSecret(secretUuid, newVaultProfileWithNewInstance.getUuid(), true);
        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions
                .assertTrue(reloadedSecret
                        .getSyncVaultProfiles()
                        .stream()
                        .noneMatch(
                                s -> s.getVaultProfile().getUuid().equals(newVaultProfileWithNewInstance.getUuid())));

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
        Assertions
                .assertThrows(ValidationException.class,
                        () -> secretService.updateSecretObjects(secretUuid, updateObjectsDto));
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
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets"))
                        .willReturn(WireMock
                                .jsonResponse(
                                        ProblemDetailExtended
                                                .fromErrorCode(ErrorCode.RESOURCE_ALREADY_EXISTS, "", null, null),
                                        HttpStatus.CONFLICT.value())
                                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PROBLEM_JSON_VALUE)));
        secretService.updateSecretObjects(secretUuid, updateObjectsDto);
        reloadedSecret = secretRepository.findWithAssociationsByUuid(secretUuid).orElseThrow();
        Assertions.assertEquals(newVaultProfile.getUuid(), reloadedSecret.getSourceVaultProfileUuid());
        Assertions
                .assertFalse(secret2SyncVaultProfileRepository
                        .findById(new Secret2SyncVaultProfileId(secretUuid, newVaultProfile.getUuid()))
                        .isPresent());
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
        WireMockServer mockServerUpdateUser = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServerUpdateUser.start();
        WireMock.configureFor("localhost", mockServerUpdateUser.port());
        mockServerUpdateUser
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/auth/users/[^/]+"))
                        .willReturn(WireMock.okJson("{ \"username\": \"newOwner\"}")));

        try {
            SecretUpdateObjectsDto updateObjectsDto = new SecretUpdateObjectsDto();
            updateObjectsDto.setOwnerUuid(String.valueOf(UUID.randomUUID()));
            secretService.updateSecretObjects(secret.getUuid(), updateObjectsDto);
            Secret reloadedSecret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
            Assertions.assertEquals("newOwner", reloadedSecret.getOwner().getOwnerUsername());
        } finally {
            mockServerUpdateUser.stop();
        }
    }

    @Test
    void testListSecrets() {
        SearchRequestDto searchRequest = new SearchRequestDto();
        searchRequest
                .setFilters(List
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_NAME.name(),
                                FilterConditionOperator.CONTAINS, secret.getName()),
                                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_TYPE.name(),
                                        FilterConditionOperator.EQUALS,
                                        (Serializable) List.of(secret.getType().getCode())),
                                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.SECRET_STATE.name(),
                                        FilterConditionOperator.EQUALS,
                                        (Serializable) List.of(secret.getState().getCode())),
                                new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                                        FilterField.SECRET_ENABLED.name(), FilterConditionOperator.EQUALS,
                                        secret.isEnabled()),
                                new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                                        FilterField.SECRET_SOURCE_VAULT_PROFILE.name(), FilterConditionOperator.EQUALS,
                                        (Serializable) List.of(secret.getSourceVaultProfile().getName())),
                                new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                                        FilterField.SECRET_SYNC_VAULT_PROFILE.name(),
                                        FilterConditionOperator.NOT_EQUALS,
                                        (Serializable) List.of(secret.getSourceVaultProfile().getName()))));
        PaginationResponseDto<SecretDto> secrets = secretService.listSecrets(searchRequest, SecurityFilter.create());
        Assertions.assertEquals(1, secrets.getTotalItems());
        Assertions.assertEquals(secret.getName(), secrets.getItems().getFirst().getName());
    }

    @Test
    void testListSecretsRefusesPageSizeAboveMaximum() {
        SearchRequestDto searchRequest = new SearchRequestDto();
        searchRequest.setItemsPerPage(1001);
        SecurityFilter securityFilter = SecurityFilter.create();
        Assertions
                .assertThrows(ValidationException.class,
                        () -> secretService.listSecrets(searchRequest, securityFilter));
    }

    @Test
    void getSecretContent_whenFingerprintCalcThrows_shouldThrowValidationException() {
        try (MockedStatic<SecretsUtil> mocked = mockStatic(SecretsUtil.class)) {
            mocked
                    .when(() -> SecretsUtil.calculateSecretContentFingerprint(any()))
                    .thenThrow(new JsonProcessingException("boom") {
                    });

            // act + assert
            UUID secretUuid = secret.getUuid();
            Assertions.assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
        }
    }

    @Test
    void getSecretContent_whenSecretDisabled_shouldNameTheSecret() {
        secret.setEnabled(false);
        secretRepository.save(secret);
        UUID secretUuid = secret.getUuid();

        // act + assert
        // the message reaches the operator as the 422 body, so it has to name the secret readably
        ValidationException thrown = Assertions
                .assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
        Assertions.assertEquals("Secret %s is not enabled".formatted(secret.getName()), thrown.getMessage());
    }

    @Test
    void getSecretContent_whenVaultProfileDisabled_shouldNameTheProfile() {
        vaultProfile.setEnabled(false);
        vaultProfileRepository.save(vaultProfile);
        UUID secretUuid = secret.getUuid();

        // act + assert
        ValidationException thrown = Assertions
                .assertThrows(ValidationException.class, () -> secretService.getSecretContent(secretUuid));
        Assertions
                .assertEquals("Source vault profile %s is not enabled".formatted(vaultProfile.getName()),
                        thrown.getMessage());
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
        List<NameAndUuidDto> secrets = secretInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, secrets.size());
        Assertions.assertEquals(secret.getName(), secrets.getFirst().getName());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = secretInternalService.getResourceObjectInternal(secret.getUuid());
        Assertions.assertEquals(secret.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(secret.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = secretInternalService.getResourceObjectExternal(secret.getSecuredUuid());
        Assertions.assertEquals(secret.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(secret.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testHandlingRejectedSecret() throws SecretOperationException, ConnectorException, NotFoundException,
            AttributeException, JsonProcessingException {
        ActionMessage actionMessage = new ActionMessage();
        actionMessage.setResourceUuid(secret.getUuid());
        actionMessage.setResourceAction(ResourceAction.CREATE);
        actionMessage.setData(SecretActionData.builder().originalState(SecretState.ACTIVE).build());
        secretInternalService.processSecretAction(actionMessage, true, false);
        secret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(SecretState.REJECTED, secret.getState());
        actionMessage.setResourceAction(ResourceAction.UPDATE);
        secretInternalService.processSecretAction(actionMessage, true, false);
        secret = secretRepository.findWithAssociationsByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertEquals(SecretState.ACTIVE, secret.getState());
    }

    @Test
    void testGetSearchableFieldInformation() {
        // Arrange: start an auth-service mock to handle the getUsers() call
        WireMockServer authServiceMock = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authServiceMock.start();
        WireMock.configureFor("localhost", authServiceMock.port());
        authServiceMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/auth/users"))
                        .willReturn(WireMock.okJson("{ \"data\": [{\"username\": \"testOwner\"}] }")));

        try {
            // Act
            List<SearchFieldDataByGroupDto> result = secretService.getSearchableFieldInformation();

            // Assert – result is present
            Assertions.assertNotNull(result);
            Assertions.assertFalse(result.isEmpty());

            // One PROPERTY group and one CUSTOM group (custom attribute was created in setUp)
            Assertions
                    .assertEquals(1,
                            result
                                    .stream()
                                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                                    .count());
            Assertions
                    .assertEquals(1,
                            result.stream().filter(g -> g.getFilterFieldSource() == FilterFieldSource.CUSTOM).count());

            // Collect all SearchFieldDataDtos from the PROPERTY group
            List<SearchFieldDataDto> propertyFields = result
                    .stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                    .map(SearchFieldDataByGroupDto::getSearchFieldData)
                    .flatMap(List::stream)
                    .toList();

            Assertions.assertEquals(FilterField.getEnumsForResource(Resource.SECRET).size(), propertyFields.size());

            // SECRET_TYPE values contain all SecretType codes
            SearchFieldDataDto secretTypeField = propertyFields
                    .stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_TYPE.name()))
                    .findFirst()
                    .orElseThrow();
            List<String> secretTypeCodes = Arrays
                    .stream(com.otilm.api.model.connector.secrets.SecretType.values())
                    .map(com.otilm.api.model.connector.secrets.SecretType::getCode)
                    .toList();
            Assertions.assertTrue(((List<?>) secretTypeField.getValue()).containsAll(secretTypeCodes));

            // SECRET_STATE values contain all SecretState codes
            SearchFieldDataDto secretStateField = propertyFields
                    .stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_STATE.name()))
                    .findFirst()
                    .orElseThrow();
            List<String> secretStateCodes = Arrays.stream(SecretState.values()).map(SecretState::getCode).toList();
            Assertions.assertTrue(((List<?>) secretStateField.getValue()).containsAll(secretStateCodes));

            // SECRET_SOURCE_VAULT_PROFILE and SECRET_SYNC_VAULT_PROFILE contain the existing vault profile name
            SearchFieldDataDto sourceVaultProfileField = propertyFields
                    .stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_SOURCE_VAULT_PROFILE.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) sourceVaultProfileField.getValue()).contains(vaultProfile.getName()));

            SearchFieldDataDto syncVaultProfileField = propertyFields
                    .stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_SYNC_VAULT_PROFILE.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) syncVaultProfileField.getValue()).contains(vaultProfile.getName()));

            // SECRET_OWNER values contain the stubbed username
            SearchFieldDataDto ownerField = propertyFields
                    .stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SECRET_OWNER.name()))
                    .findFirst()
                    .orElseThrow();
            Assertions.assertTrue(((List<?>) ownerField.getValue()).contains("testOwner"));

        } finally {
            authServiceMock.stop();
        }
    }

    @Test
    void publishesTheActionMessageAfterCommit_whenASecretIsCreated() throws Exception {
        // given
        // Read from a separate REQUIRES_NEW transaction: a publish before commit leaves the secret invisible there,
        // exactly as it is to the real listener's own transaction.
        final AtomicBoolean secretVisibleFromSeparateTransaction = new AtomicBoolean();
        final TransactionTemplate separateTransaction = new TransactionTemplate(transactionManager);
        separateTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        Mockito.doAnswer(invocation -> {
            ActionMessage msg = invocation.getArgument(0);
            secretVisibleFromSeparateTransaction
                    .set(separateTransaction
                            .execute(status -> secretRepository.findByUuid(msg.getResourceUuid()).isPresent()));
            return null;
        }).when(actionProducer).produceMessage(any());
        var request = new SecretRequestDto();
        request.setName("afterCommitSecret");
        request.setSecret(new BasicAuthSecretContent());

        // when
        secretService.createSecret(request, vaultInstance.getSecuredParentUuid(), vaultProfile.getUuid());

        // then
        assertThat(secretVisibleFromSeparateTransaction.get())
                .as("action message must be published only after the creating transaction commits")
                .isTrue();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** An action on the secret, as the broker hands it to the listener. */
    private ActionMessage secretAction(ResourceAction action, Object data) {
        ActionMessage message = new ActionMessage();
        message.setResource(Resource.SECRET);
        message.setResourceAction(action);
        message.setResourceUuid(secret.getUuid());
        message.setData(data);
        return message;
    }

    private VaultProfile persistVaultProfileOnAnotherVault() {
        VaultInstance otherVaultInstance = new VaultInstance();
        otherVaultInstance.setName("newVaultInstance");
        otherVaultInstance.setConnector(connector);
        vaultInstanceRepository.save(otherVaultInstance);
        VaultProfile otherVaultProfile = new VaultProfile();
        otherVaultProfile.setName("newVaultProfileNewInstance");
        otherVaultProfile.setVaultInstance(otherVaultInstance);
        return vaultProfileRepository.save(otherVaultProfile);
    }

    /** What an action on the secret carries; a source vault profile change moves it to the given profile. */
    private static SecretActionData buildActionData(VaultProfile newSourceVaultProfile) throws JsonProcessingException {
        return SecretActionData
                .builder()
                .originalState(SecretState.ACTIVE)
                .updatedSourceVaultProfileUuid(newSourceVaultProfile.getUuid())
                .attributes(List.of())
                .encryptedContent(encryptEmptyBasicAuthContent())
                .deleteInVault(Boolean.TRUE)
                .build();
    }

    private static String encryptEmptyBasicAuthContent() throws JsonProcessingException {
        return SecretsUtil
                .encryptAndEncodeSecretString(new ObjectMapper().writeValueAsString(new BasicAuthSecretContent()),
                        SecretEncodingVersion.V1);
    }
}
