package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@SpringBootTest
@Transactional
@Rollback
class TokenProfileServiceTest extends BaseSpringBootTest {

    private static final String TOKEN_PROFILE_NAME = "testTokenProfile1";

    @Autowired
    private TokenProfileService tokenProfileService;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private TokenProfile tokenProfile;
    private TokenInstanceReference tokenInstanceReference;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference = tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName(TOKEN_PROFILE_NAME);
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setEnabled(true);
        tokenProfile = tokenProfileRepository.save(tokenProfile);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListTokenProfiles() {
        List<TokenProfileDto> tokenProfiles = tokenProfileService.listTokenProfiles(
                Optional.of(true),
                SecurityFilter.create()
        );
        Assertions.assertNotNull(tokenProfiles);
        Assertions.assertFalse(tokenProfiles.isEmpty());
        Assertions.assertEquals(1, tokenProfiles.size());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), tokenProfiles.get(0).getUuid());
    }

    @Test
    void testGetTokenProfileByUuid() throws NotFoundException {
        TokenProfileDetailDto dto = tokenProfileService.getTokenProfile(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid()
        );
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(tokenProfile.getUuid().toString(), dto.getUuid());
    }

    @Test
    void testGetTokenProfileByUuid_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.getTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")
                )
        );
    }

    @Test
    void testAddTokenProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        request.setName("testTokenProfile2");
        request.setAttributes(List.of());
        request.setDescription("sample description");

        TokenProfileDetailDto dto = tokenProfileService.createTokenProfile(
                tokenInstanceReference.getSecuredParentUuid(),
                request
        );
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testAddTokenProfile_validationFail() {
        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        Assertions.assertThrows(
                ValidationException.class,
                () -> tokenProfileService.createTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        request
                )
        );
    }

    @Test
    void testAddTokenProfile_alreadyExist() {
        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        request.setName(TOKEN_PROFILE_NAME); // tokenProfile with same username exist

        Assertions.assertThrows(
                AlreadyExistException.class,
                () -> tokenProfileService.createTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        request
                )
        );
    }

    @Test
    void testEditTokenProfile() throws ConnectorException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        EditTokenProfileRequestDto request = new EditTokenProfileRequestDto();
        request.setDescription("updated description");
        request.setAttributes(List.of());

        TokenProfileDetailDto dto = tokenProfileService.editTokenProfile(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                request
        );
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testEditTokenProfile_notFound() {
        EditTokenProfileRequestDto request = new EditTokenProfileRequestDto();
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.editTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                        request)
        );
    }

    @Test
    void testRemoveTokenProfile() throws NotFoundException {
        tokenProfileService.deleteTokenProfile(tokenProfile.getSecuredUuid());
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.getTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid()
                )
        );
    }

    @Test
    void testRemoveTokenProfile_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.deleteTokenProfile(
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")
                )
        );
    }

    @Test
    void testEnableTokenProfile() throws NotFoundException {
        tokenProfileService.enableTokenProfile(
                tokenProfile.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid()
        );
        Assertions.assertEquals(
                true,
                tokenProfile.getEnabled()
        );
    }

    @Test
    void testEnableTokenProfile_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.enableTokenProfile(
                        tokenProfile.getSecuredParentUuid(),
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")
                )
        );
    }

    @Test
    void testDisableTokenProfile() throws NotFoundException {
        tokenProfileService.disableTokenProfile(
                tokenProfile.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid()
        );
        Assertions.assertEquals(
                false,
                tokenProfile.getEnabled()
        );
    }

    @Test
    void testDisableTokenProfile_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> tokenProfileService.disableTokenProfile(
                        tokenProfile.getSecuredParentUuid(),
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")
                )
        );
    }


    @Test
    void testBulkRemove() {
        tokenProfileService.deleteTokenProfile(List.of(tokenProfile.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class,
                () -> tokenProfileService.getTokenProfile(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid()
                )
        );
    }

    @Test
    void testBulkEnable() {
        tokenProfileService.enableTokenProfile(List.of(tokenProfile.getSecuredUuid()));
        Assertions.assertTrue(tokenProfile.getEnabled());
    }

    @Test
    void testBulkDisable() {
        tokenProfileService.disableTokenProfile(List.of(tokenProfile.getSecuredUuid()));
        Assertions.assertFalse(tokenProfile.getEnabled());
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> response = tokenProfileService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, response.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = tokenProfileService.getResourceObjectInternal(tokenProfile.getUuid());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = tokenProfileService.getResourceObjectExternal(tokenProfile.getSecuredUuid());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenProfile.getName(), nameAndUuidDto.getName());
    }
}
