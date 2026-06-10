package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.vault.*;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.repository.*;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.otilm.core.dao.entity.Connector;
import org.springframework.http.HttpStatus;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

class VaultInstanceServiceTest extends BaseSpringBootTest {

    public static final String TEST_CUSTOM_ATTRIBUTE = "testCustomAttribute";
    @Autowired
    private VaultInstanceService vaultInstanceService;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private AttributeService attributeService;
    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    private Connector connector;
    private VaultInstance vaultInstance;
    private WireMockServer mockServer;
    private ConnectorInterfaceEntity interfaceEntity;


    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(
                WireMock.get(WireMock.urlPathMatching("/v1/secretProvider/vaults/attributes"))
                        .willReturn(WireMock.okJson("[]"))
        );
        mockServer.stubFor(
                WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/vaults"))
                        .willReturn(WireMock.ok())
        );

        connector = new Connector();
        connector.setName("testConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);

        // Add connector interface
        interfaceEntity = new ConnectorInterfaceEntity();
        interfaceEntity.setConnectorUuid(connector.getUuid());
        interfaceEntity.setInterfaceCode(ConnectorInterface.SECRET);
        interfaceEntity.setVersion("v2");
        interfaceEntity.setFeatures(List.of(FeatureFlag.STATELESS));
        connectorInterfaceRepository.save(interfaceEntity);

        vaultInstance = new VaultInstance();
        vaultInstance.setConnector(connector);
        vaultInstance.setConnectorUuid(connector.getUuid());
        vaultInstance.setName("testVaultInstance");
        vaultInstanceRepository.save(vaultInstance);

        VaultProfile profile = new VaultProfile();
        profile.setVaultInstance(vaultInstance);
        profile.setVaultInstanceUuid(vaultInstance.getUuid());
        profile.setName("testProfile");
        vaultProfileRepository.save(profile);

        CustomAttributeCreateRequestDto dto = new CustomAttributeCreateRequestDto();
        dto.setName(TEST_CUSTOM_ATTRIBUTE);
        dto.setLabel("Test Attribute");
        dto.setContentType(AttributeContentType.STRING);
        dto.setResources(List.of(Resource.VAULT));
        attributeService.createCustomAttribute(dto);
    }

    @Test
    void testListAttributes() throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException {
        GroupAttributeV3 groupAttributeV3 = new GroupAttributeV3();
        groupAttributeV3.setName("test");
        groupAttributeV3.setUuid(UUID.randomUUID().toString());
        groupAttributeV3.setAttributeCallback(new AttributeCallback());
        DataAttributeV3 dataAttributeV3 = new DataAttributeV3();
        dataAttributeV3.setName("test2");
        dataAttributeV3.setUuid(UUID.randomUUID().toString());
        dataAttributeV3.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        dataAttributeV3.setProperties(properties);
        dataAttributeV3.setAttributeCallback(new AttributeCallback());

        mockServer.stubFor(
                WireMock.get(WireMock.urlPathMatching("/v1/secretProvider/vaults/attributes"))
                        .willReturn(WireMock.jsonResponse(new ObjectMapper().writeValueAsString(List.of(groupAttributeV3, dataAttributeV3)), HttpStatus.OK.value()))
        );
        List<BaseAttribute> attributes = vaultInstanceService.listVaultInstanceAttributes(connector.getUuid());
        Assertions.assertNotNull(attributes);
        Assertions.assertEquals(2, attributes.size());
        Assertions.assertEquals(groupAttributeV3.getName(), attributes.get(0).getName());
        Assertions.assertEquals(dataAttributeV3.getName(), attributes.get(1).getName());
        Assertions.assertEquals(3, attributeDefinitionRepository.count());
    }

    @Test
    void testCreateVaultInstance() throws ConnectorException, NotFoundException, AttributeException, AlreadyExistException {
        VaultInstanceRequestDto requestDto = new VaultInstanceRequestDto();
        requestDto.setName(vaultInstance.getName());
        requestDto.setConnectorUuid(connector.getUuid());
        requestDto.setInterfaceUuid(UUID.randomUUID());
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        requestDto.setCustomAttributes(List.of(attribute));
        requestDto.setDescription("description");
        Assertions.assertThrows(AlreadyExistException.class, () -> vaultInstanceService.createVaultInstance(requestDto));
        requestDto.setName("test2");
        Assertions.assertThrows(ValidationException.class, () -> vaultInstanceService.createVaultInstance(requestDto));
        requestDto.setInterfaceUuid(interfaceEntity.getUuid());
        VaultInstanceDetailDto vaultInstanceDetailDto = vaultInstanceService.createVaultInstance(requestDto);
        Assertions.assertNotNull(vaultInstanceDetailDto);
        Assertions.assertEquals(requestDto.getName(), vaultInstanceDetailDto.getName());
        Assertions.assertNotNull(vaultInstanceDetailDto.getUuid());
        Assertions.assertEquals(requestDto.getDescription(), vaultInstanceDetailDto.getDescription());
        Assertions.assertNotNull(vaultInstanceDetailDto.getConnector());
        Assertions.assertEquals(requestDto.getConnectorUuid().toString(), vaultInstanceDetailDto.getConnector().getUuid());
        Assertions.assertNotNull(vaultInstanceDetailDto.getCustomAttributes());
        Assertions.assertEquals(1, vaultInstanceDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), vaultInstanceDetailDto.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data", ((List<AttributeContent>) vaultInstanceDetailDto.getCustomAttributes().getFirst().getContent()).getFirst().getData());
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testGetVaultInstance() throws ConnectorException, NotFoundException, AttributeException {
        Assertions.assertThrows(NotFoundException.class, () -> vaultInstanceService.getVaultInstance(UUID.randomUUID()));
        VaultInstanceDetailDto vaultInstanceDetailDto = vaultInstanceService.getVaultInstance(vaultInstance.getUuid());
        Assertions.assertNotNull(vaultInstanceDetailDto);
        Assertions.assertEquals(vaultInstance.getName(), vaultInstanceDetailDto.getName());
        Assertions.assertEquals(vaultInstance.getDescription(), vaultInstanceDetailDto.getDescription());
        Assertions.assertEquals(vaultInstance.getConnectorUuid().toString(), vaultInstanceDetailDto.getConnector().getUuid());
    }

    @Test
    void testListVaultInstances() {
        SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(List.of(
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.VAULT_INSTANCE_CONNECTOR_NAME.name(), FilterConditionOperator.EQUALS, (Serializable) List.of(connector.getName())),
                new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.VAULT_INSTANCE_NAME.name(), FilterConditionOperator.EQUALS, vaultInstance.getName())
        ));
        PaginationResponseDto<VaultInstanceDto> vaultInstanceListResponseDto = vaultInstanceService.listVaultInstances(searchRequestDto, SecurityFilter.create());
        Assertions.assertNotNull(vaultInstanceListResponseDto);
        Assertions.assertEquals(1, vaultInstanceListResponseDto.getTotalItems());
        Assertions.assertEquals(1, vaultInstanceListResponseDto.getItems().size());
        Assertions.assertEquals(vaultInstance.getName(), vaultInstanceListResponseDto.getItems().getFirst().getName());
    }

    @Test
    void testDeleteVaultInstance() throws NotFoundException {
        UUID vaultInstanceUuid = vaultInstance.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> vaultInstanceService.deleteVaultInstance(vaultInstanceUuid));
        vaultProfileRepository.deleteAll();
        vaultInstanceService.deleteVaultInstance(vaultInstanceUuid);
        Assertions.assertThrows(NotFoundException.class, () -> vaultInstanceService.getVaultInstance(vaultInstanceUuid));
    }

    @Test
    void testUpdateVaultInstance() throws NotFoundException, AttributeException, ConnectorException {
        VaultInstanceUpdateRequestDto requestDto = new VaultInstanceUpdateRequestDto();
        Assertions.assertThrows(NotFoundException.class, () -> vaultInstanceService.updateVaultInstance(UUID.randomUUID(), requestDto));
        requestDto.setDescription("new description");
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setName(TEST_CUSTOM_ATTRIBUTE);
        attribute.setContent(List.of(new StringAttributeContentV3("ref", "data")));
        requestDto.setCustomAttributes(List.of(attribute));
        VaultInstanceDetailDto vaultInstanceDetailDto = vaultInstanceService.updateVaultInstance(vaultInstance.getUuid(), requestDto);
        Assertions.assertNotNull(vaultInstanceDetailDto);
        Assertions.assertEquals(requestDto.getDescription(), vaultInstanceDetailDto.getDescription());
        Assertions.assertEquals(1, vaultInstanceDetailDto.getCustomAttributes().size());
        Assertions.assertEquals(attribute.getName(), vaultInstanceDetailDto.getCustomAttributes().getFirst().getName());
        Assertions.assertEquals("data", ((List<AttributeContent>) vaultInstanceDetailDto.getCustomAttributes().getFirst().getContent()).getFirst().getData());
    }

    @Test
    void testListVaultProfileAttributes_notFound() {
        SecuredUUID nonExistentUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        Assertions.assertThrows(NotFoundException.class, () -> vaultInstanceService.listVaultProfileAttributes(nonExistentUuid));
    }

    @Test
    void testListVaultProfileAttributes_noConnector() {
        VaultInstance vaultInstanceWithoutConnector = new VaultInstance();
        vaultInstanceWithoutConnector.setName("noConnectorVaultInstance");
        // connectorUuid intentionally not set
        vaultInstanceRepository.save(vaultInstanceWithoutConnector);

        SecuredUUID uuid = SecuredUUID.fromUUID(vaultInstanceWithoutConnector.getUuid());
        Assertions.assertThrows(ValidationException.class, () -> vaultInstanceService.listVaultProfileAttributes(uuid));
    }

    @Test
    void testListVaultProfileAttributes() throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException {
        DataAttributeV3 profileAttribute = new DataAttributeV3();
        profileAttribute.setName("profileAttr");
        profileAttribute.setUuid(UUID.randomUUID().toString());
        profileAttribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Profile Attribute Label");
        profileAttribute.setProperties(properties);

        mockServer.stubFor(
                WireMock.post(WireMock.urlPathMatching("/v1/secretProvider/vaultProfiles/attributes"))
                        .willReturn(WireMock.jsonResponse(new ObjectMapper().writeValueAsString(List.of(profileAttribute)), HttpStatus.OK.value()))
        );

        List<BaseAttribute> attributes = vaultInstanceService.listVaultProfileAttributes(SecuredUUID.fromUUID(vaultInstance.getUuid()));
        Assertions.assertNotNull(attributes);
        Assertions.assertEquals(1, attributes.size());
        Assertions.assertEquals(profileAttribute.getName(), attributes.getFirst().getName());
    }

    @Test
    void testGetSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchableFieldInformation = vaultInstanceService.getSearchableFieldInformation();
        Assertions.assertNotNull(searchableFieldInformation);
        Assertions.assertEquals(1, searchableFieldInformation.stream().filter(s -> s.getFilterFieldSource() == FilterFieldSource.CUSTOM).count());
        SearchFieldDataDto connectorNameSearchData = searchableFieldInformation.stream().filter(s -> s.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                .map(SearchFieldDataByGroupDto::getSearchFieldData).flatMap(List::stream)
                .filter(s -> s.getFieldIdentifier().equals(FilterField.VAULT_INSTANCE_CONNECTOR_NAME.name())).findFirst().get();
        Assertions.assertEquals(connector.getName(), ((List<String>) connectorNameSearchData.getValue()).getFirst());
        SearchFieldDataDto nameSearchData = searchableFieldInformation.stream().filter(s -> s.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                .map(SearchFieldDataByGroupDto::getSearchFieldData).flatMap(List::stream)
                .filter(s -> s.getFieldIdentifier().equals(FilterField.VAULT_INSTANCE_NAME.name())).findFirst().get();
        Assertions.assertNotNull(nameSearchData);
    }

}
