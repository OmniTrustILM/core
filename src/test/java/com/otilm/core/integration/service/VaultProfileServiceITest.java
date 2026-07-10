package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.api.model.core.vaultprofile.*;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.VaultProfileExternalService;
import com.otilm.core.service.VaultProfileInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;


class VaultProfileServiceITest extends BaseSpringBootTest {

    public static final String TEST_CUSTOM_ATTRIBUTE = "testCustomAttribute";

    @Autowired
    private VaultProfileExternalService vaultProfileService;

    @Autowired
    private VaultProfileInternalService vaultProfileInternalService;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;
    @Autowired
    private Secret2SyncVaultProfileRepository secret2SyncVaultProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private VaultProfile vaultProfile;
    private VaultInstance vaultInstance;
    private WireMockServer mockServer;
    private Connector connector;

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/vaultProfiles/attributes"))
                .willReturn(WireMock.okJson("[]")));

        connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);

        vaultInstance = new VaultInstance();
        vaultInstance.setName("testInstance");
        vaultInstanceRepository.save(vaultInstance);

        vaultProfile = new VaultProfile();
        vaultProfile.setName("testProfile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfileRepository.save(vaultProfile);

        CustomAttributeCreateRequestDto dto = new CustomAttributeCreateRequestDto();
        dto.setName(TEST_CUSTOM_ATTRIBUTE);
        dto.setLabel("Test Attribute");
        dto.setContentType(AttributeContentType.STRING);
        dto.setResources(List.of(Resource.VAULT_PROFILE));
        attributeService.createCustomAttribute(dto);
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.resetAll();
            mockServer.stop();
        }
    }

    @Test
    void testCreateVaultProfile() throws NotFoundException, AttributeException, AlreadyExistException {
        VaultProfileRequestDto requestDto = new VaultProfileRequestDto();
        requestDto.setName(vaultProfile.getName());
        Assertions.assertThrows(AlreadyExistException.class, () -> vaultProfileService.createVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), requestDto));
        requestDto.setName("testProfile2");
        requestDto.setDescription("test description");
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        requestDto.setCustomAttributes(List.of(attribute));
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.createVaultProfile(SecuredParentUUID.fromUUID(UUID.randomUUID()), requestDto));
        Assertions.assertThrows(ValidationException.class, () -> vaultProfileService.createVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), requestDto));

        vaultInstance.setConnector(connector);
        vaultInstance.setConnectorUuid(connector.getUuid());
        vaultInstance = vaultInstanceRepository.save(vaultInstance);

        VaultProfileDetailDto createdProfile = vaultProfileService.createVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), requestDto);
        Assertions.assertNotNull(createdProfile);
        Assertions.assertEquals(requestDto.getName(), createdProfile.getName());
        Assertions.assertNotNull(createdProfile.getUuid());
        Assertions.assertEquals(requestDto.getDescription(), createdProfile.getDescription());
        Assertions.assertEquals(vaultInstance.getUuid().toString(), createdProfile.getVaultInstance().getUuid());
        Assertions.assertNotNull(createdProfile.getCustomAttributes());
        Assertions.assertEquals(1, createdProfile.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), createdProfile.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data", ((List<AttributeContent>) createdProfile.getCustomAttributes().getFirst().getContent()).getFirst().getData());
    }

    @Test
    void testUpdateVaultProfile() throws NotFoundException, AttributeException {
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.updateVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(UUID.randomUUID()), new VaultProfileUpdateRequestDto()));
        VaultProfileUpdateRequestDto requestDto = new VaultProfileUpdateRequestDto();
        requestDto.setDescription("new description");
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        requestDto.setCustomAttributes(List.of(attribute));

        Assertions.assertThrows(ValidationException.class, () -> vaultProfileService.updateVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()), requestDto));

        vaultInstance.setConnector(connector);
        vaultInstance.setConnectorUuid(connector.getUuid());
        vaultInstance = vaultInstanceRepository.save(vaultInstance);
        VaultProfileDetailDto detailDto = vaultProfileService.updateVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()), requestDto);

        Assertions.assertNotNull(detailDto);
        Assertions.assertEquals(requestDto.getDescription(), detailDto.getDescription());
        Assertions.assertEquals(vaultInstance.getUuid().toString(), detailDto.getVaultInstance().getUuid());
        Assertions.assertNotNull(detailDto.getCustomAttributes());
        Assertions.assertEquals(1, detailDto.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), detailDto.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data", ((List<AttributeContent>) detailDto.getCustomAttributes().getFirst().getContent()).getFirst().getData());
    }

    @Test
    void testDeleteVaultProfile() throws NotFoundException {
        SecuredParentUUID vaultUuid = SecuredParentUUID.fromUUID(vaultInstance.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.deleteVaultProfile(vaultUuid, SecuredUUID.fromUUID(UUID.randomUUID())));

        Secret secret = new Secret();
        secret.setName("testSecret");
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());

        SecretVersion secretVersion = new SecretVersion();
        secretVersion.setVaultProfile(vaultProfile);
        secretVersion.setFingerprint("testFingerprint");
        secretVersionRepository.save(secretVersion);

        secret.setLatestVersionUuid(secretVersion.getUuid());
        secretRepository.save(secret);

        secretVersion.setSecret(secret);
        secretVersion.setSecretUuid(secret.getUuid());
        secretVersionRepository.save(secretVersion);

        SecuredUUID profileUuid = SecuredUUID.fromUUID(vaultProfile.getUuid());
        Assertions.assertThrows(ValidationException.class, () -> vaultProfileService.deleteVaultProfile(vaultUuid, profileUuid));

        VaultProfile vaultProfile2 = new VaultProfile();
        vaultProfile2.setName("testProfile2");
        vaultProfile2.setVaultInstance(vaultInstance);
        vaultProfile2.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfileRepository.save(vaultProfile2);
        secret.setSourceVaultProfile(vaultProfile2);
        secret.setSourceVaultProfileUuid(vaultProfile2.getUuid());
        secretRepository.save(secret);
        secretVersion.setVaultProfileUuid(vaultProfile2.getUuid());
        secretVersionRepository.save(secretVersion);

        Secret2SyncVaultProfileId secret2SyncVaultProfileId = new Secret2SyncVaultProfileId();
        secret2SyncVaultProfileId.setSecretUuid(secret.getUuid());
        secret2SyncVaultProfileId.setVaultProfileUuid(vaultProfile.getUuid());
        Secret2SyncVaultProfile secret2SyncVaultProfile = new Secret2SyncVaultProfile();
        secret2SyncVaultProfile.setId(secret2SyncVaultProfileId);
        secret2SyncVaultProfile.setSecret(secret);
        secret2SyncVaultProfile.setVaultProfile(vaultProfile);
        secret2SyncVaultProfileRepository.save(secret2SyncVaultProfile);

        Assertions.assertThrows(ValidationException.class, () -> vaultProfileService.deleteVaultProfile(vaultUuid, profileUuid));

        secret2SyncVaultProfileRepository.delete(secret2SyncVaultProfile);

        vaultProfileService.deleteVaultProfile(vaultUuid, profileUuid);
        Assertions.assertNull(vaultProfileRepository.findByUuid(profileUuid).orElse(null));
    }


    @Test
    void testGetVaultProfile() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.getVaultProfileDetails(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(UUID.randomUUID())));
        VaultProfileDetailDto detailDto = vaultProfileService.getVaultProfileDetails(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()));
        Assertions.assertNotNull(detailDto);
        Assertions.assertEquals(vaultProfile.getName(), detailDto.getName());
        Assertions.assertEquals(vaultProfile.getDescription(), detailDto.getDescription());
        Assertions.assertEquals(vaultInstance.getUuid().toString(), detailDto.getVaultInstance().getUuid());
    }

    @Test
    void testListVaultProfiles() {
        SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(List.of(
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.VAULT_PROFILE_NAME.name(), FilterConditionOperator.CONTAINS, vaultProfile.getName()),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.VAULT_PROFILE_VAULT_INSTANCE.name(), FilterConditionOperator.EQUALS, (java.io.Serializable) List.of(vaultInstance.getName()))
        ));
        PaginationResponseDto<VaultProfileDto> profiles = vaultProfileService.listVaultProfiles(searchRequestDto, SecurityFilter.create());
        Assertions.assertEquals(1, profiles.getItems().size());
        Assertions.assertEquals(vaultProfile.getUuid().toString(), profiles.getItems().getFirst().getUuid());
    }

    @Test
    void testEnableVaultProfile() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.enableVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(UUID.randomUUID())));
        vaultProfileService.enableVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()));
        VaultProfile updatedProfile = vaultProfileRepository.findByUuid(SecuredUUID.fromUUID(vaultProfile.getUuid())).orElseThrow();
        Assertions.assertTrue(updatedProfile.isEnabled());
    }

    @Test
    void testDisableVaultProfile() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> vaultProfileService.disableVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(UUID.randomUUID())));
        vaultProfileService.disableVaultProfile(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()));
        VaultProfile updatedProfile = vaultProfileRepository.findByUuid(SecuredUUID.fromUUID(vaultProfile.getUuid())).orElseThrow();
        Assertions.assertFalse(updatedProfile.isEnabled());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        List<NameAndUuidDto> dtos = vaultProfileInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());

        NameAndUuidDto dto = vaultProfileInternalService.getResourceObjectExternal(SecuredUUID.fromUUID(vaultProfile.getUuid()));
        Assertions.assertEquals(vaultProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(vaultProfile.getName(), dto.getName());

        dto = vaultProfileInternalService.getResourceObjectInternal(vaultProfile.getUuid());
        Assertions.assertEquals(vaultProfile.getUuid().toString(), dto.getUuid());
    }

    @Test
    void testListSecretAttributes() throws NotFoundException, ConnectorException, AttributeException {
        vaultInstance.setConnector(connector);
        vaultInstance.setConnectorUuid(connector.getUuid());
        vaultInstanceRepository.save(vaultInstance);

        String secretType = SecretType.GENERIC.getCode();
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/v1/secretProvider/secrets/" + secretType + "/attributes"))
                .willReturn(WireMock.okJson("[{\"uuid\":\"2d648f63-bf0a-4aff-8861-842cb60a77bb\", \"name\":\"testAttribute\", \"type\":\"data\", \"contentType\":\"string\", \"properties\":{\"label\":\"Test Attribute\", \"required\":false, \"readOnly\":false, \"visible\":true}}]")));

        List<BaseAttribute> attributes = vaultProfileService.listSecretAttributes(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()), SecretType.GENERIC);
        Assertions.assertNotNull(attributes);
        Assertions.assertEquals(1, attributes.size());
        Assertions.assertEquals("testAttribute", attributes.getFirst().getName());
    }

    @Test
    void testListSecretAttributes_NoConnector() {
        vaultInstance.setConnector(null);
        vaultInstance.setConnectorUuid(null);
        vaultInstanceRepository.save(vaultInstance);

        Assertions.assertThrows(ValidationException.class, () -> vaultProfileService.listSecretAttributes(SecuredParentUUID.fromUUID(vaultInstance.getUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()), SecretType.GENERIC));
    }

    @Test
    void testGetSearchableFieldInformation() {
        var searchableFields = vaultProfileService.getSearchableFieldInformation();
        Assertions.assertNotNull(searchableFields);
        Assertions.assertFalse(searchableFields.isEmpty());
        var propertyGroup = searchableFields.stream().filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY).findFirst().orElseThrow();
        Assertions.assertNotNull(propertyGroup);
        Assertions.assertTrue(propertyGroup.getSearchFieldData().stream().anyMatch(f -> f.getFieldIdentifier().equals(FilterField.VAULT_PROFILE_NAME.name())));
        Assertions.assertTrue(propertyGroup.getSearchFieldData().stream().anyMatch(f -> f.getFieldIdentifier().equals(FilterField.VAULT_PROFILE_VAULT_INSTANCE.name())));
    }

}
