package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AttributeRelation;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AttributeRelationRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TspProfileServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "a1b2c3d4-0001-0002-0003-000000000002";
    private static final String CUSTOM_ATTR_NAME = "tspTestAttribute";

    @Autowired
    private TspProfileService tspService;

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    private TspProfileRepository tspRepository;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @MockitoSpyBean
    private TspProfileRepository tspRepositorySpy;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private TspProfileBasicCredentialRepository basicCredentialRepository;

    @MockitoBean
    private SecretService secretService;

    private TspProfile savedTspProfile;

    @BeforeEach
    void setUp() {
        // Create a TSP profile entity directly for tests that need pre-existing data
        savedTspProfile = new TspProfile();
        savedTspProfile.setName("existing-tsp-profile");
        savedTspProfile.setDescription("Existing TSP profile description");
        savedTspProfile = tspRepository.save(savedTspProfile);

        // Register a custom attribute available for TSP Profile resources
        CustomAttributeV3 attrDef = new CustomAttributeV3();
        attrDef.setUuid(CUSTOM_ATTR_UUID);
        attrDef.setName(CUSTOM_ATTR_NAME);
        attrDef.setDescription("test custom attribute for TSP profile");
        attrDef.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties props = new CustomAttributeProperties();
        props.setReadOnly(false);
        props.setRequired(false);
        attrDef.setProperties(props);

        AttributeDefinition attributeDefinition = new AttributeDefinition();
        attributeDefinition.setUuid(UUID.fromString(CUSTOM_ATTR_UUID));
        attributeDefinition.setName(CUSTOM_ATTR_NAME);
        attributeDefinition.setAttributeUuid(UUID.fromString(CUSTOM_ATTR_UUID));
        attributeDefinition.setContentType(AttributeContentType.STRING);
        attributeDefinition.setLabel(CUSTOM_ATTR_NAME);
        attributeDefinition.setType(AttributeType.CUSTOM);
        attributeDefinition.setDefinition(attrDef);
        attributeDefinition.setEnabled(true);
        attributeDefinition.setVersion(3);
        attributeDefinitionRepository.save(attributeDefinition);

        AttributeRelation attributeRelation = new AttributeRelation();
        attributeRelation.setResource(Resource.TSP_PROFILE);
        attributeRelation.setAttributeDefinitionUuid(attributeDefinition.getUuid());
        attributeRelationRepository.save(attributeRelation);

        when(secretService.getLatestFingerprintsByUuid(any())).thenReturn(Map.of());
    }

    private TspProfileBasicCredential persistBasicCredential(TspProfile profile, String username, UUID secretUuid) {
        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        credential.setUsername(username);
        credential.setSecretUuid(secretUuid);
        credential.setMappedUserUuid(UUID.randomUUID());
        return basicCredentialRepository.save(credential);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // List
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListTspProfiles_returnsExistingEntries() {
        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        assertNotNull(response);
        assertNotNull(response.getItems());
        assertEquals(1, response.getTotalItems());
        assertEquals(savedTspProfile.getUuid().toString(), response.getItems().getFirst().getUuid());
        assertEquals(savedTspProfile.getName(), response.getItems().getFirst().getName());
    }

    @Test
    void testListTspProfiles_withoutDefaultSigningProfile_signingUrlIsNull() {
        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        assertEquals(1, response.getTotalItems());
        assertNull(response.getItems().getFirst().getSigningUrl(),
                "signingUrl must be null on the list DTO when no default signing profile is set");
    }

    @Test
    void testListTspProfiles_withDefaultSigningProfile_returnsSigningUrl() {
        SigningProfile signingProfile = new SigningProfile();
        signingProfile.setName("default-signing-profile-for-list");
        signingProfile.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        signingProfile.setSigningScheme(SigningScheme.MANAGED);
        signingProfile.setLatestVersion(1);
        signingProfile.setEnabled(true);
        signingProfile = signingProfileRepository.saveAndFlush(signingProfile);

        savedTspProfile.setDefaultSigningProfile(signingProfile);
        savedTspProfile = tspRepository.save(savedTspProfile);

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        TspProfileListDto listDto = response.getItems().getFirst();
        assertNotNull(listDto.getSigningUrl(),
                "signingUrl must be populated on the list DTO when a default signing profile is set");
        assertTrue(listDto.getSigningUrl().endsWith("/v1/protocols/tsp/" + savedTspProfile.getName() + "/sign"),
                "Unexpected signingUrl: " + listDto.getSigningUrl());
    }

    @Test
    void testListTspProfiles_emptyWhenNoneExist() {
        tspRepository.delete(savedTspProfile);

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        assertNotNull(response);
        assertEquals(0, response.getTotalItems());
        assertTrue(response.getItems().isEmpty());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testGetTspProfile_returnsCorrectDto() throws NotFoundException {
        TspProfileDto dto = tspService.getTspProfile(savedTspProfile.getSecuredUuid());

        assertNotNull(dto);
        assertEquals(savedTspProfile.getUuid().toString(), dto.getUuid());
        assertEquals(savedTspProfile.getName(), dto.getName());
        assertEquals(savedTspProfile.getDescription(), dto.getDescription());
        assertNull(dto.getVaultProfile());
    }

    @Test
    void testGetTspProfile_notFound() {
        assertThrows(NotFoundException.class,
                () -> tspService.getTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testGetTspProfileEntity_returnsCorrectEntity() throws NotFoundException {
        TspProfile entity = tspService.getTspProfileEntity(savedTspProfile.getSecuredUuid());

        assertNotNull(entity);
        assertEquals(savedTspProfile.getUuid(), entity.getUuid());
        assertEquals(savedTspProfile.getName(), entity.getName());
    }

    @Test
    void testGetTspProfileEntity_notFound() {
        assertThrows(NotFoundException.class,
                () -> tspService.getTspProfileEntity(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Find all names
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testFindAllNames_returnsExistingNames() {
        List<String> names = tspService.findAllNames();

        assertNotNull(names);
        assertEquals(1, names.size());
        assertTrue(names.contains(savedTspProfile.getName()));
    }

    @Test
    void testFindAllNames_returnsAllWhenMultipleExist() {
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        tspRepository.save(second);

        List<String> names = tspService.findAllNames();

        assertEquals(2, names.size());
        assertTrue(names.contains(savedTspProfile.getName()));
        assertTrue(names.contains("second-tsp-profile"));
    }

    @Test
    void testFindAllNames_emptyWhenNoneExist() {
        tspRepository.delete(savedTspProfile);

        List<String> names = tspService.findAllNames();

        assertNotNull(names);
        assertTrue(names.isEmpty());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTspProfile_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("new-tsp-profile");
        request.setDescription("New TSP profile description");

        TspProfileDto dto = tspService.createTspProfile(request);

        // Assert returned DTO
        assertNotNull(dto);
        assertNotNull(dto.getUuid());
        assertEquals("new-tsp-profile", dto.getName());
        assertEquals("New TSP profile description", dto.getDescription());

        // Assert entity reloaded from the database
        Optional<TspProfile> fromDb = tspRepository.findById(UUID.fromString(dto.getUuid()));
        assertTrue(fromDb.isPresent());
        TspProfile entity = fromDb.get();
        assertEquals("new-tsp-profile", entity.getName());
        assertEquals("New TSP profile description", entity.getDescription());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Update
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testUpdateTspProfile_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("updated-tsp-profile");
        request.setDescription("Updated description");

        TspProfileDto dto = tspService.updateTspProfile(savedTspProfile.getSecuredUuid(), request);

        // Assert returned DTO
        assertNotNull(dto);
        assertEquals(savedTspProfile.getUuid().toString(), dto.getUuid());
        assertEquals("updated-tsp-profile", dto.getName());
        assertEquals("Updated description", dto.getDescription());

        // Assert entity reloaded from the database
        Optional<TspProfile> fromDb = tspRepository.findById(savedTspProfile.getUuid());
        assertTrue(fromDb.isPresent());
        TspProfile entity = fromDb.get();
        assertEquals("updated-tsp-profile", entity.getName());
        assertEquals("Updated description", entity.getDescription());
    }

    @Test
    void testUpdateTspProfile_notFound_throwsNotFoundException() {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("does-not-matter");

        assertThrows(NotFoundException.class,
                () -> tspService.updateTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"), request));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testDeleteTspProfile_removesEntityFromDatabase() throws NotFoundException {
        tspService.deleteTspProfile(savedTspProfile.getSecuredUuid());

        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
        assertThrows(NotFoundException.class,
                () -> tspService.getTspProfile(savedTspProfile.getSecuredUuid()));
    }

    @Test
    void testDeleteTspProfile_notFound_throwsNotFoundException() {
        assertThrows(NotFoundException.class,
                () -> tspService.deleteTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDeleteTspProfile_deletesAssociatedBasicCredentialSecrets() throws Exception {
        UUID secretUuid = UUID.randomUUID();
        persistBasicCredential(savedTspProfile, "svc-account", secretUuid);

        tspService.deleteTspProfile(savedTspProfile.getSecuredUuid());

        verify(secretService, times(1)).deleteSecret(secretUuid, true);
        assertTrue(basicCredentialRepository.findByTspProfileUuid(savedTspProfile.getUuid()).isEmpty(),
                "Basic credential rows must be removed when the TSP profile is deleted");
        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
    }

    @Test
    void testDeleteTspProfile_deletesSecretsForAllBasicCredentials() throws Exception {
        UUID firstSecret = UUID.randomUUID();
        UUID secondSecret = UUID.randomUUID();
        persistBasicCredential(savedTspProfile, "svc-one", firstSecret);
        persistBasicCredential(savedTspProfile, "svc-two", secondSecret);

        tspService.deleteTspProfile(savedTspProfile.getSecuredUuid());

        verify(secretService, times(1)).deleteSecret(firstSecret, true);
        verify(secretService, times(1)).deleteSecret(secondSecret, true);
        assertTrue(basicCredentialRepository.findByTspProfileUuid(savedTspProfile.getUuid()).isEmpty());
        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
    }

    @Test
    void testDeleteTspProfile_vaultFailureForOneSecretDoesNotBlockTeardown() throws Exception {
        UUID failingSecret = UUID.randomUUID();
        UUID succeedingSecret = UUID.randomUUID();
        persistBasicCredential(savedTspProfile, "svc-fails", failingSecret);
        persistBasicCredential(savedTspProfile, "svc-succeeds", succeedingSecret);

        doThrow(new ConnectorException("vault unavailable"))
                .when(secretService).deleteSecret(failingSecret, true);

        tspService.deleteTspProfile(savedTspProfile.getSecuredUuid());

        verify(secretService, times(1)).deleteSecret(failingSecret, true);
        verify(secretService, times(1)).deleteSecret(succeedingSecret, true);
        assertTrue(basicCredentialRepository.findByTspProfileUuid(savedTspProfile.getUuid()).isEmpty(),
                "A vault failure on one secret must not leave credential rows behind");
        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent(),
                "Profile teardown must complete even when a vault secret delete fails");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Bulk delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testBulkDeleteTspProfiles_removesAllEntities() {
        // Create a second profile
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second = tspRepository.save(second);

        List<BulkActionMessageDto> messages = tspService.bulkDeleteTspProfiles(
                List.of(savedTspProfile.getSecuredUuid(), second.getSecuredUuid()));

        assertNotNull(messages);
        assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
        assertFalse(tspRepository.findById(second.getUuid()).isPresent());
    }

    @Test
    void testBulkDeleteTspProfiles_partialFailure_returnsErrorMessages() {
        UUID nonExistent = UUID.fromString("00000000-0000-0000-0000-000000000001");
        List<BulkActionMessageDto> messages = tspService.bulkDeleteTspProfiles(
                List.of(savedTspProfile.getSecuredUuid(), SecuredUUID.fromUUID(nonExistent)));

        assertNotNull(messages);
        assertEquals(1, messages.size(), "Expected exactly one error for the unknown profile");
        assertEquals(nonExistent.toString(), messages.getFirst().getUuid());

        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Enable / disable
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testEnableTspProfile_setsEnabledTrue() throws NotFoundException {
        assertFalse(savedTspProfile.isEnabled(), "TSP profile should start disabled");

        tspService.enableTspProfile(savedTspProfile.getSecuredUuid());

        TspProfile fromDb = tspRepository.findById(savedTspProfile.getUuid()).orElseThrow();
        assertTrue(fromDb.isEnabled());
    }

    @Test
    void testDisableTspProfile_setsEnabledFalse() throws NotFoundException {
        // Pre-enable the entity directly in the DB
        savedTspProfile.setEnabled(true);
        tspRepository.save(savedTspProfile);

        tspService.disableTspProfile(savedTspProfile.getSecuredUuid());

        TspProfile fromDb = tspRepository.findById(savedTspProfile.getUuid()).orElseThrow();
        assertFalse(fromDb.isEnabled());
    }

    @Test
    void testEnableTspProfile_notFound_throwsNotFoundException() {
        assertThrows(NotFoundException.class,
                () -> tspService.enableTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDisableTspProfile_notFound_throwsNotFoundException() {
        assertThrows(NotFoundException.class,
                () -> tspService.disableTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testBulkEnableTspProfiles_enablesAll() {
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second = tspRepository.save(second);

        List<BulkActionMessageDto> messages = tspService.bulkEnableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid(), second.getSecuredUuid()));

        assertNotNull(messages);
        assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        assertTrue(tspRepository.findById(savedTspProfile.getUuid()).orElseThrow().isEnabled());
        assertTrue(tspRepository.findById(second.getUuid()).orElseThrow().isEnabled());
    }

    @Test
    void testBulkDisableTspProfiles_disablesAll() {
        // Pre-enable both entities
        savedTspProfile.setEnabled(true);
        tspRepository.save(savedTspProfile);

        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second.setEnabled(true);
        second = tspRepository.save(second);

        List<BulkActionMessageDto> messages = tspService.bulkDisableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid(), second.getSecuredUuid()));

        assertNotNull(messages);
        assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        assertFalse(tspRepository.findById(savedTspProfile.getUuid()).orElseThrow().isEnabled());
        assertFalse(tspRepository.findById(second.getUuid()).orElseThrow().isEnabled());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Custom attributes
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTspProfile_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("tsp-value-on-create")));

        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("tsp-with-custom-attr");
        request.setCustomAttributes(List.of(customAttr));

        TspProfileDto dto = tspService.createTspProfile(request);

        assertNotNull(dto.getCustomAttributes());
        assertFalse(dto.getCustomAttributes().isEmpty(),
                "Custom attributes should be returned in the create DTO");
        assertEquals("tsp-value-on-create",
                ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    @Test
    void testUpdateTspProfile_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 createAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("initial-value")));
        TspProfileRequestDto createRequest = new TspProfileRequestDto();
        createRequest.setName("tsp-update-custom-attr");
        createRequest.setCustomAttributes(List.of(createAttr));
        TspProfileDto created = tspService.createTspProfile(createRequest);

        RequestAttributeV3 updateAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("updated-value")));
        TspProfileRequestDto updateRequest = new TspProfileRequestDto();
        updateRequest.setName("tsp-update-custom-attr");
        updateRequest.setCustomAttributes(List.of(updateAttr));
        TspProfileDto updated = tspService.updateTspProfile(
                SecuredUUID.fromString(created.getUuid()), updateRequest);

        assertNotNull(updated.getCustomAttributes());
        assertFalse(updated.getCustomAttributes().isEmpty());
        assertEquals("updated-value",
                ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Name uniqueness
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTspProfile_duplicateName_throwsAlreadyExistException() {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());

        assertThrows(AlreadyExistException.class,
                () -> tspService.createTspProfile(request));
    }

    @Test
    void testUpdateTspProfile_toExistingNameOfAnotherProfile_throwsAlreadyExistException() throws AttributeException, NotFoundException {
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        tspRepository.save(second);

        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());

        assertThrows(AlreadyExistException.class,
                () -> tspService.updateTspProfile(second.getSecuredUuid(), request));
    }

    @Test
    void testUpdateTspProfile_keepingSameName_succeeds() throws AlreadyExistException, AttributeException, NotFoundException {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());
        request.setDescription("updated description");

        TspProfileDto dto = tspService.updateTspProfile(savedTspProfile.getSecuredUuid(), request);

        assertEquals(savedTspProfile.getName(), dto.getName());
        assertEquals("updated description", dto.getDescription());
    }

    @Test
    void testBulkEnableTspProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = tspService.bulkEnableTspProfiles(List.of(nonExistent));

        assertEquals(1, messages.size());
        assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDisableTspProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = tspService.bulkDisableTspProfiles(List.of(nonExistent));

        assertEquals(1, messages.size());
        assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        assertNotNull(messages.getFirst().getMessage());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Bulk-op catch-block entity-name branches (profile != null path)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testBulkDeleteTspProfiles_deleteFailure_returnsErrorWithProfileName() {
        doThrow(new RuntimeException("DB error during delete"))
                .when(tspRepositorySpy).delete(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkDeleteTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        assertEquals(1, messages.size());
        assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkEnableTspProfiles_saveFailure_returnsErrorWithProfileName() {
        doThrow(new RuntimeException("DB error during save"))
                .when(tspRepositorySpy).save(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkEnableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        assertEquals(1, messages.size());
        assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDisableTspProfiles_saveFailure_returnsErrorWithProfileName() {
        doThrow(new RuntimeException("DB error during save"))
                .when(tspRepositorySpy).save(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkDisableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        assertEquals(1, messages.size());
        assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        assertNotNull(messages.getFirst().getMessage());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Vault profile nesting in create/update response
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTspProfile_withVaultProfile_returnsNestedVaultProfile() throws Exception {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("testInstance");
        vaultInstanceRepository.save(vaultInstance);

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("testVaultProfile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfileRepository.save(vaultProfile);

        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("tsp-with-vault");
        request.setAllowedAuthenticationMethods(List.of(TspAuthenticationMethod.BASIC_PASSWORD));
        request.setVaultProfileUuid(vaultProfile.getUuid());

        TspProfileDto dto = tspService.createTspProfile(request);

        assertNotNull(dto.getVaultProfile(), "vaultProfile in response DTO must not be null");
        assertEquals(vaultProfile.getUuid().toString(), dto.getVaultProfile().getUuid());
        assertEquals("testVaultProfile", dto.getVaultProfile().getName());
        assertNotNull(dto.getVaultProfile().getVaultInstance());
        assertEquals(vaultInstance.getUuid().toString(), dto.getVaultProfile().getVaultInstance().getUuid());
    }
}
