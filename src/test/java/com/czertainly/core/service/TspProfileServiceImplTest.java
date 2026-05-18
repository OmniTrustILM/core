package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.AttributeDefinition;
import com.czertainly.core.dao.entity.AttributeRelation;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.AttributeDefinitionRepository;
import com.czertainly.core.dao.repository.AttributeRelationRepository;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

class TspProfileServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "a1b2c3d4-0001-0002-0003-000000000002";
    private static final String CUSTOM_ATTR_NAME = "tspTestAttribute";

    @Autowired
    private TspProfileService tspService;

    @Autowired
    private ResourceService resourceService;

    @Autowired
    private TspProfileRepository tspRepository;

    @MockitoSpyBean
    private TspProfileRepository tspRepositorySpy;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

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
    }

    // ──────────────────────────────────────────────────────────────────────────
    // List
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListTspProfiles_returnsExistingEntries() {
        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertNotNull(response.getItems());
        Assertions.assertEquals(1, response.getTotalItems());
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), response.getItems().getFirst().getUuid());
        Assertions.assertEquals(savedTspProfile.getName(), response.getItems().getFirst().getName());
    }

    @Test
    void testListTspProfiles_emptyWhenNoneExist() {
        tspRepository.delete(savedTspProfile);

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TspProfileListDto> response = tspService.listTspProfiles(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(0, response.getTotalItems());
        Assertions.assertTrue(response.getItems().isEmpty());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testGetTspProfile_returnsCorrectDto() throws NotFoundException {
        TspProfileDto dto = tspService.getTspProfile(savedTspProfile.getSecuredUuid());

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(savedTspProfile.getName(), dto.getName());
        Assertions.assertEquals(savedTspProfile.getDescription(), dto.getDescription());
    }

    @Test
    void testGetTspProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> tspService.getTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
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
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());
        Assertions.assertEquals("new-tsp-profile", dto.getName());
        Assertions.assertEquals("New TSP profile description", dto.getDescription());

        // Assert entity reloaded from the database
        Optional<TspProfile> fromDb = tspRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        TspProfile entity = fromDb.get();
        Assertions.assertEquals("new-tsp-profile", entity.getName());
        Assertions.assertEquals("New TSP profile description", entity.getDescription());
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
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals("updated-tsp-profile", dto.getName());
        Assertions.assertEquals("Updated description", dto.getDescription());

        // Assert entity reloaded from the database
        Optional<TspProfile> fromDb = tspRepository.findById(savedTspProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        TspProfile entity = fromDb.get();
        Assertions.assertEquals("updated-tsp-profile", entity.getName());
        Assertions.assertEquals("Updated description", entity.getDescription());
    }

    @Test
    void testUpdateTspProfile_notFound_throwsNotFoundException() {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("does-not-matter");

        Assertions.assertThrows(NotFoundException.class,
                () -> tspService.updateTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"), request));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testDeleteTspProfile_removesEntityFromDatabase() throws NotFoundException {
        tspService.deleteTspProfile(savedTspProfile.getSecuredUuid());

        Assertions.assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
        Assertions.assertThrows(NotFoundException.class,
                () -> tspService.getTspProfile(savedTspProfile.getSecuredUuid()));
    }

    @Test
    void testDeleteTspProfile_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> tspService.deleteTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
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

        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        Assertions.assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
        Assertions.assertFalse(tspRepository.findById(second.getUuid()).isPresent());
    }

    @Test
    void testBulkDeleteTspProfiles_partialFailure_returnsErrorMessages() {
        UUID nonExistent = UUID.fromString("00000000-0000-0000-0000-000000000001");
        List<BulkActionMessageDto> messages = tspService.bulkDeleteTspProfiles(
                List.of(savedTspProfile.getSecuredUuid(), SecuredUUID.fromUUID(nonExistent)));

        Assertions.assertNotNull(messages);
        Assertions.assertEquals(1, messages.size(), "Expected exactly one error for the unknown profile");
        Assertions.assertEquals(nonExistent.toString(), messages.getFirst().getUuid());

        Assertions.assertFalse(tspRepository.findById(savedTspProfile.getUuid()).isPresent());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Enable / disable
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testEnableTspProfile_setsEnabledTrue() throws NotFoundException {
        Assertions.assertFalse(savedTspProfile.isEnabled(), "TSP profile should start disabled");

        tspService.enableTspProfile(savedTspProfile.getSecuredUuid());

        TspProfile fromDb = tspRepository.findById(savedTspProfile.getUuid()).orElseThrow();
        Assertions.assertTrue(fromDb.isEnabled());
    }

    @Test
    void testDisableTspProfile_setsEnabledFalse() throws NotFoundException {
        // Pre-enable the entity directly in the DB
        savedTspProfile.setEnabled(true);
        tspRepository.save(savedTspProfile);

        tspService.disableTspProfile(savedTspProfile.getSecuredUuid());

        TspProfile fromDb = tspRepository.findById(savedTspProfile.getUuid()).orElseThrow();
        Assertions.assertFalse(fromDb.isEnabled());
    }

    @Test
    void testEnableTspProfile_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> tspService.enableTspProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDisableTspProfile_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
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

        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        Assertions.assertTrue(tspRepository.findById(savedTspProfile.getUuid()).orElseThrow().isEnabled());
        Assertions.assertTrue(tspRepository.findById(second.getUuid()).orElseThrow().isEnabled());
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

        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        Assertions.assertFalse(tspRepository.findById(savedTspProfile.getUuid()).orElseThrow().isEnabled());
        Assertions.assertFalse(tspRepository.findById(second.getUuid()).orElseThrow().isEnabled());
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

        Assertions.assertNotNull(dto.getCustomAttributes());
        Assertions.assertFalse(dto.getCustomAttributes().isEmpty(),
                "Custom attributes should be returned in the create DTO");
        Assertions.assertEquals("tsp-value-on-create",
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

        Assertions.assertNotNull(updated.getCustomAttributes());
        Assertions.assertFalse(updated.getCustomAttributes().isEmpty());
        Assertions.assertEquals("updated-value",
                ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Name uniqueness
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTspProfile_duplicateName_throwsAlreadyExistException() {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());

        Assertions.assertThrows(AlreadyExistException.class,
                () -> tspService.createTspProfile(request));
    }

    @Test
    void testUpdateTspProfile_toExistingNameOfAnotherProfile_throwsAlreadyExistException() throws AttributeException, NotFoundException {
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        tspRepository.save(second);

        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());

        Assertions.assertThrows(AlreadyExistException.class,
                () -> tspService.updateTspProfile(second.getSecuredUuid(), request));
    }

    @Test
    void testUpdateTspProfile_keepingSameName_succeeds() throws AlreadyExistException, AttributeException, NotFoundException {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(savedTspProfile.getName());
        request.setDescription("updated description");

        TspProfileDto dto = tspService.updateTspProfile(savedTspProfile.getSecuredUuid(), request);

        Assertions.assertEquals(savedTspProfile.getName(), dto.getName());
        Assertions.assertEquals("updated description", dto.getDescription());
    }

    @Test
    void testBulkEnableTspProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = tspService.bulkEnableTspProfiles(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDisableTspProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = tspService.bulkDisableTspProfiles(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Bulk-op catch-block entity-name branches (profile != null path)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testBulkDeleteTspProfiles_deleteFailure_returnsErrorWithProfileName() {
        org.mockito.Mockito.doThrow(new RuntimeException("DB error during delete"))
                .when(tspRepositorySpy).delete(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkDeleteTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkEnableTspProfiles_saveFailure_returnsErrorWithProfileName() {
        org.mockito.Mockito.doThrow(new RuntimeException("DB error during save"))
                .when(tspRepositorySpy).save(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkEnableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDisableTspProfiles_saveFailure_returnsErrorWithProfileName() {
        org.mockito.Mockito.doThrow(new RuntimeException("DB error during save"))
                .when(tspRepositorySpy).save(ArgumentMatchers.any());

        List<BulkActionMessageDto> messages = tspService.bulkDisableTspProfiles(
                List.of(savedTspProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(savedTspProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(savedTspProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}
