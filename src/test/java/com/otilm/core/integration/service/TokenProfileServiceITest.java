package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TokenProfileInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TokenProfileServiceITest extends BaseSpringBootTest {

    private static final String TOKEN_PROFILE_NAME = "testTokenProfile1";

    @Autowired
    private TokenProfileExternalService tokenProfileService;
    @Autowired
    private TokenProfileInternalService tokenProfileInternalService;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private SigningProfileRepository signingProfileRepository;
    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    private TokenProfile tokenProfile;
    private TokenInstanceReference tokenInstanceReference;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setStatus(TokenInstanceStatus.UNKNOWN);
        tokenInstanceReference = tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName(TOKEN_PROFILE_NAME);
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setEnabled(true);
        tokenProfile = tokenProfileRepository.save(tokenProfile);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListTokenProfiles() {
        List<TokenProfileDto> tokenProfiles = tokenProfileService
                .listTokenProfiles(Optional.of(true), SecurityFilter.create());
        Assertions.assertNotNull(tokenProfiles);
        Assertions.assertFalse(tokenProfiles.isEmpty());
        Assertions.assertEquals(1, tokenProfiles.size());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), tokenProfiles.get(0).getUuid());
    }

    @Test
    void listTokenProfiles_includesProfileWhoseTokenHasNoConnector() {
        // given
        var disconnectedProfile = createDisconnectedProfile();
        var disconnectedProfileUuid = disconnectedProfile.getUuid().toString();

        // when
        List<TokenProfileDto> tokenProfiles = tokenProfileService
                .listTokenProfiles(Optional.of(true), SecurityFilter.create());

        // then
        Assertions
                .assertTrue(
                        tokenProfiles.stream().anyMatch(profile -> disconnectedProfileUuid.equals(profile.getUuid())));
    }

    @Test
    void getTokenProfile_returnsProfileWhoseTokenHasNoConnector() throws NotFoundException {
        // given
        var disconnectedProfile = createDisconnectedProfile();
        var disconnectedTokenUuid = disconnectedProfile.getTokenInstanceReference().getSecuredParentUuid();

        // when
        TokenProfileDetailDto detail = tokenProfileService
                .getTokenProfile(disconnectedTokenUuid, disconnectedProfile.getSecuredUuid());

        // then
        Assertions.assertEquals(disconnectedProfile.getUuid().toString(), detail.getUuid());
        Assertions.assertEquals(TokenInstanceStatus.UNKNOWN, detail.getTokenInstanceStatus());
    }

    @Test
    void deleteTokenProfile_deletesProfileWhoseTokenHasNoConnector() throws NotFoundException {
        // given
        var disconnectedProfile = createDisconnectedProfile();
        var disconnectedTokenUuid = disconnectedProfile.getTokenInstanceReference().getSecuredParentUuid();
        var disconnectedProfileUuid = disconnectedProfile.getSecuredUuid();

        // when
        tokenProfileService.deleteTokenProfile(disconnectedTokenUuid, disconnectedProfileUuid);

        // then
        Assertions.assertTrue(tokenProfileRepository.findByUuid(disconnectedProfileUuid).isEmpty());
    }

    @Test
    void testGetTokenProfileByUuid() throws NotFoundException {
        TokenProfileDetailDto dto = tokenProfileService
                .getTokenProfile(tokenInstanceReference.getSecuredParentUuid(), tokenProfile.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(tokenProfile.getUuid().toString(), dto.getUuid());
    }

    @Test
    void testGetTokenProfileByUuid_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenProfileService
                                .getTokenProfile(tokenInstanceReference.getSecuredParentUuid(),
                                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void scopedEdit_throwsNotFoundException_forProfileOwnedByAnotherToken() {
        // given
        String originalDescription = "original description";
        String attemptedDescription = "must not be applied";
        TokenInstanceReference anotherToken = new TokenInstanceReference();
        anotherToken.setTokenInstanceUuid("another-persisted-token");
        anotherToken.setConnector(connector);
        anotherToken.setStatus(TokenInstanceStatus.UNKNOWN);
        anotherToken = tokenInstanceReferenceRepository.save(anotherToken);
        tokenProfile.setDescription(originalDescription);
        tokenProfile = tokenProfileRepository.save(tokenProfile);
        stubTokenProfileAttributeValidation();
        var request = new EditTokenProfileRequestDto();
        request.setDescription(attemptedDescription);
        request.setAttributes(List.of());
        var tokenProfileUuid = tokenProfile.getSecuredUuid();
        var anotherTokenUuid = anotherToken.getSecuredParentUuid();

        // when
        Executable edit = () -> tokenProfileService.editTokenProfile(anotherTokenUuid, tokenProfileUuid, request);

        // then
        Assertions.assertThrows(NotFoundException.class, edit);
        TokenProfile unchangedProfile = tokenProfileRepository.findByUuid(tokenProfileUuid).orElseThrow();
        Assertions.assertEquals(tokenInstanceReference.getUuid(), unchangedProfile.getTokenInstanceReferenceUuid());
        Assertions.assertEquals(originalDescription, unchangedProfile.getDescription());
    }

    @Test
    void testAddTokenProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        stubTokenProfileAttributeValidation();

        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        request.setName("testTokenProfile2");
        request.setAttributes(List.of());
        request.setDescription("sample description");

        TokenProfileDetailDto dto = tokenProfileService
                .createTokenProfile(tokenInstanceReference.getSecuredParentUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testAddTokenProfile_validationFail() {
        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        var securedParentUuid = tokenInstanceReference.getSecuredParentUuid();
        Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.createTokenProfile(securedParentUuid, request));
    }

    @Test
    void testAddTokenProfile_alreadyExist() {
        AddTokenProfileRequestDto request = new AddTokenProfileRequestDto();
        request.setName(TOKEN_PROFILE_NAME); // tokenProfile with same username exist

        Assertions
                .assertThrows(AlreadyExistException.class, () -> tokenProfileService
                        .createTokenProfile(tokenInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    void testEditTokenProfile() throws ConnectorException, AttributeException, NotFoundException {
        stubTokenProfileAttributeValidation();

        EditTokenProfileRequestDto request = new EditTokenProfileRequestDto();
        request.setDescription("updated description");
        request.setAttributes(List.of());

        TokenProfileDetailDto dto = tokenProfileService
                .editTokenProfile(tokenInstanceReference.getSecuredParentUuid(), tokenProfile.getSecuredUuid(),
                        request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testEditTokenProfile_notFound() {
        EditTokenProfileRequestDto request = new EditTokenProfileRequestDto();
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenProfileService
                                .editTokenProfile(tokenInstanceReference.getSecuredParentUuid(),
                                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    void testRemoveTokenProfile() throws NotFoundException {
        tokenProfileService
                .deleteTokenProfile(tokenProfile.getTokenInstanceReference().getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid());
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenProfileService
                        .getTokenProfile(tokenInstanceReference.getSecuredParentUuid(), tokenProfile.getSecuredUuid()));
    }

    @Test
    void testRemoveTokenProfile_withDependentKeys() {
        createKey("testKey1");
        createKey("testKey2");

        SecuredUUID tokenProfileUuid = tokenProfile.getSecuredUuid();
        SecuredParentUUID tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.deleteTokenProfile(tokenInstanceUuid, tokenProfileUuid));

        String errors = joinErrorDescriptions(e);
        Assertions
                .assertTrue(
                        errors.contains("Cannot delete Token Profile " + TOKEN_PROFILE_NAME + ": 2 dependent Key(s)"),
                        errors);
        Assertions.assertTrue(tokenProfileRepository.findByUuid(tokenProfileUuid).isPresent());
        Assertions.assertEquals(2, cryptographicKeyRepository.countByTokenProfileUuid(tokenProfileUuid.getValue()));
    }

    @Test
    void testRemoveTokenProfile_withDependentSigningProfile() {
        SigningProfile signingProfile = createSigningProfile("testSigningProfile", 1);
        createSigningProfileVersion(signingProfile, 1, tokenProfile);

        SecuredUUID tokenProfileUuid = tokenProfile.getSecuredUuid();
        SecuredParentUUID tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.deleteTokenProfile(tokenInstanceUuid, tokenProfileUuid));

        String errors = joinErrorDescriptions(e);
        Assertions
                .assertTrue(errors
                        .contains("Cannot delete Token Profile " + TOKEN_PROFILE_NAME
                                + ": dependent Signing Profile(s): testSigningProfile"),
                        errors);
    }

    @Test
    void testRemoveTokenProfile_withSupersededSigningProfileVersion() {
        SigningProfile signingProfile = createSigningProfile("testSigningProfile", 2);
        createSigningProfileVersion(signingProfile, 1, tokenProfile);
        createSigningProfileVersion(signingProfile, 2, null);

        SecuredUUID tokenProfileUuid = tokenProfile.getSecuredUuid();
        SecuredParentUUID tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.deleteTokenProfile(tokenInstanceUuid, tokenProfileUuid));

        String errors = joinErrorDescriptions(e);
        Assertions
                .assertTrue(errors
                        .contains(
                                "Signing Profile(s) referencing it only in superseded versions (released only by deleting the Signing Profile): testSigningProfile"),
                        errors);
        Assertions.assertFalse(errors.contains("dependent Signing Profile(s)"), errors);
    }

    @Test
    void testRemoveTokenProfile_signingProfileReferencingInLatestAndSupersededVersion() {
        SigningProfile signingProfile = createSigningProfile("testSigningProfile", 2);
        createSigningProfileVersion(signingProfile, 1, tokenProfile);
        createSigningProfileVersion(signingProfile, 2, tokenProfile);

        SecuredUUID tokenProfileUuid = tokenProfile.getSecuredUuid();
        SecuredParentUUID tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.deleteTokenProfile(tokenInstanceUuid, tokenProfileUuid));

        String errors = joinErrorDescriptions(e);
        Assertions.assertTrue(errors.contains("dependent Signing Profile(s): testSigningProfile"), errors);
        Assertions.assertFalse(errors.contains("superseded"), errors);
    }

    @Test
    void testRemoveTokenProfile_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenProfileService
                        .deleteTokenProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableTokenProfile() throws NotFoundException {
        // given
        var tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();

        // when
        tokenProfileService.enableTokenProfile(tokenInstanceUuid, tokenProfileUuid);

        // then
        Assertions.assertTrue(tokenProfileRepository.findByUuid(tokenProfileUuid).orElseThrow().getEnabled());
    }

    @Test
    void testEnableTokenProfile_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenProfileService
                                .enableTokenProfile(tokenInstanceReference.getSecuredParentUuid(),
                                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableTokenProfile() throws NotFoundException {
        // given
        var tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();

        // when
        tokenProfileService.disableTokenProfile(tokenInstanceUuid, tokenProfileUuid);

        // then
        Assertions.assertFalse(tokenProfileRepository.findByUuid(tokenProfileUuid).orElseThrow().getEnabled());
    }

    @Test
    void testDisableTokenProfile_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> tokenProfileService
                                .disableTokenProfile(tokenInstanceReference.getSecuredParentUuid(),
                                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() {
        tokenProfileService.deleteTokenProfile(List.of(tokenProfile.getSecuredUuid()));
        Assertions
                .assertThrows(NotFoundException.class, () -> tokenProfileService
                        .getTokenProfile(tokenInstanceReference.getSecuredParentUuid(), tokenProfile.getSecuredUuid()));
    }

    @Test
    void testBulkRemove_skipsProfilesWithDependents() {
        TokenProfile cleanProfile = new TokenProfile();
        cleanProfile.setName("testTokenProfile2");
        cleanProfile.setTokenInstanceReference(tokenInstanceReference);
        cleanProfile.setEnabled(true);
        cleanProfile = tokenProfileRepository.save(cleanProfile);
        createKey("testKey1");

        tokenProfileService.deleteTokenProfile(List.of(cleanProfile.getSecuredUuid(), tokenProfile.getSecuredUuid()));

        // Best-effort semantics: deletable profiles are removed, blocked ones are skipped (logged),
        // consistent with how the bulk loop treats NotFoundException. Per-item error reporting
        // (BulkActionMessageDto contract) is tracked as a follow-up.
        Assertions.assertTrue(tokenProfileRepository.findByUuid(cleanProfile.getSecuredUuid()).isEmpty());
        Assertions.assertTrue(tokenProfileRepository.findByUuid(tokenProfile.getSecuredUuid()).isPresent());
    }

    @Test
    void testRemoveTokenProfile_withMultipleBlockerTypes() {
        createKey("testKey1");
        SigningProfile signingProfile = createSigningProfile("testSigningProfile", 1);
        createSigningProfileVersion(signingProfile, 1, tokenProfile);

        SecuredUUID tokenProfileUuid = tokenProfile.getSecuredUuid();
        SecuredParentUUID tokenInstanceUuid = tokenInstanceReference.getSecuredParentUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> tokenProfileService.deleteTokenProfile(tokenInstanceUuid, tokenProfileUuid));

        String errors = joinErrorDescriptions(e);
        Assertions
                .assertTrue(
                        errors
                                .contains("Cannot delete Token Profile " + TOKEN_PROFILE_NAME
                                        + ": 1 dependent Key(s); dependent Signing Profile(s): testSigningProfile"),
                        errors);
    }

    @Test
    void testBulkEnable() {
        // given
        var tokenProfileUuid = tokenProfile.getSecuredUuid();

        // when
        tokenProfileService.enableTokenProfile(List.of(tokenProfileUuid));

        // then
        Assertions.assertTrue(tokenProfileRepository.findByUuid(tokenProfileUuid).orElseThrow().getEnabled());
    }

    @Test
    void testBulkDisable() {
        // given
        var tokenProfileUuid = tokenProfile.getSecuredUuid();

        // when
        tokenProfileService.disableTokenProfile(List.of(tokenProfileUuid));

        // then
        Assertions.assertFalse(tokenProfileRepository.findByUuid(tokenProfileUuid).orElseThrow().getEnabled());
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> response = tokenProfileInternalService
                .listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, response.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = tokenProfileInternalService.getResourceObjectInternal(tokenProfile.getUuid());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = tokenProfileInternalService.getResourceObjectExternal(tokenProfile.getSecuredUuid());
        Assertions.assertEquals(tokenProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(tokenProfile.getName(), nameAndUuidDto.getName());
    }

    private TokenProfile createDisconnectedProfile() {
        TokenInstanceReference disconnectedToken = new TokenInstanceReference();
        disconnectedToken.setTokenInstanceUuid("disconnected-token");
        disconnectedToken.setStatus(TokenInstanceStatus.UNKNOWN);
        disconnectedToken = tokenInstanceReferenceRepository.save(disconnectedToken);

        TokenProfile disconnectedProfile = new TokenProfile();
        disconnectedProfile.setName("profile-without-connector");
        disconnectedProfile.setEnabled(true);
        disconnectedProfile.setTokenInstanceReference(disconnectedToken);
        return tokenProfileRepository.save(disconnectedProfile);
    }

    private SigningProfile createSigningProfile(String name, int latestVersion) {
        SigningProfile signingProfile = new SigningProfile();
        signingProfile.setName(name);
        signingProfile.setSigningScheme(SigningScheme.DELEGATED);
        signingProfile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        signingProfile.setLatestVersion(latestVersion);
        return signingProfileRepository.save(signingProfile);
    }

    private SigningProfileVersion createSigningProfileVersion(SigningProfile signingProfile, int version,
            TokenProfile referencedTokenProfile) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(signingProfile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersion.setTokenProfile(referencedTokenProfile);
        return signingProfileVersionRepository.save(profileVersion);
    }

    private CryptographicKey createKey(String name) {
        CryptographicKey key = new CryptographicKey();
        key.setName(name);
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);
        return cryptographicKeyRepository.save(key);
    }

    private void stubTokenProfileAttributeValidation() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/tokenProfile/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
    }

    private static String joinErrorDescriptions(ValidationException e) {
        return e.getErrors().stream().map(ValidationError::getErrorDescription).collect(Collectors.joining("; "));
    }
}
