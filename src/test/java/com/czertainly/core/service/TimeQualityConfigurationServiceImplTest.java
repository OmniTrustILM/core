package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.AttributeDefinition;
import com.czertainly.core.dao.entity.AttributeRelation;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.AttributeDefinitionRepository;
import com.czertainly.core.dao.repository.AttributeRelationRepository;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.mockito.ArgumentMatchers.any;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

class TimeQualityConfigurationServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "b1c2d3e4-0001-0002-0003-000000000003";
    private static final String CUSTOM_ATTR_NAME = "tqcTestAttribute";

    @Autowired
    private TimeQualityConfigurationService timeQualityConfigurationService;

    @MockitoSpyBean
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;

    @MockitoSpyBean
    private AttributeEngine attributeEngine;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    /**
     * A pre-existing TimeQualityConfiguration saved directly via repository.
     */
    private TimeQualityConfiguration savedConfiguration;

    @AfterEach
    void resetSpies() {
        Mockito.reset(timeQualityConfigurationRepository, attributeEngine);
    }

    @BeforeEach
    void setUp() {
        savedConfiguration = new TimeQualityConfiguration();
        savedConfiguration.setName("existing-tq-config");
        savedConfiguration.setAccuracy(Duration.ofSeconds(1));
        savedConfiguration.setNtpServers(List.of("pool.ntp.org"));
        savedConfiguration.setNtpCheckInterval(Duration.ofSeconds(30));
        savedConfiguration.setNtpSamplesPerServer(4);
        savedConfiguration.setNtpCheckTimeout(Duration.ofSeconds(5));
        savedConfiguration.setNtpServersMinReachable(1);
        savedConfiguration.setMaxClockDrift(Duration.ofSeconds(1));
        savedConfiguration.setLeapSecondGuard(true);
        savedConfiguration = timeQualityConfigurationRepository.save(savedConfiguration);

        // Register a custom attribute available for Time Quality Configuration resources
        CustomAttributeV3 attrDef = new CustomAttributeV3();
        attrDef.setUuid(CUSTOM_ATTR_UUID);
        attrDef.setName(CUSTOM_ATTR_NAME);
        attrDef.setDescription("test custom attribute for Time Quality config");
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
        attributeRelation.setResource(Resource.TIME_QUALITY_CONFIGURATION);
        attributeRelation.setAttributeDefinitionUuid(attributeDefinition.getUuid());
        attributeRelationRepository.save(attributeRelation);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private TimeQualityConfigurationRequestDto buildCreateRequest(String name) {
        TimeQualityConfigurationRequestDto request = new TimeQualityConfigurationRequestDto();
        request.setName(name);
        request.setAccuracy(Duration.ofSeconds(1));
        request.setNtpServers(List.of("pool.ntp.org", "time.google.com"));
        request.setNtpCheckInterval(Duration.ofSeconds(30));
        request.setNtpSamplesPerServer(4);
        request.setNtpCheckTimeout(Duration.ofSeconds(5));
        request.setNtpServersMinReachable(1);
        request.setMaxClockDrift(Duration.ofSeconds(1));
        request.setLeapSecondGuard(true);
        return request;
    }

    private TimeQualityConfigurationRequestDto buildUpdateRequest(String name) {
        TimeQualityConfigurationRequestDto request = new TimeQualityConfigurationRequestDto();
        request.setName(name);
        request.setAccuracy(Duration.ofMillis(500));
        request.setNtpServers(List.of("time.cloudflare.com"));
        request.setNtpCheckInterval(Duration.ofSeconds(60));
        request.setNtpSamplesPerServer(8);
        request.setNtpCheckTimeout(Duration.ofSeconds(10));
        request.setNtpServersMinReachable(2);
        request.setMaxClockDrift(Duration.ofMillis(500));
        request.setLeapSecondGuard(false);
        return request;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // List
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListTimeQualityConfigurations_returnsExistingEntry() {
        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TimeQualityConfigurationListDto> response =
                timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(1, response.getTotalItems());
        TimeQualityConfigurationListDto listed = response.getItems().getFirst();
        Assertions.assertEquals(savedConfiguration.getUuid().toString(), listed.getUuid());
        Assertions.assertEquals("existing-tq-config", listed.getName());
        Assertions.assertEquals(List.of("pool.ntp.org"), listed.getNtpServers());
    }

    @Test
    void testListTimeQualityConfigurations_emptyWhenNoneExist() {
        timeQualityConfigurationRepository.delete(savedConfiguration);

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TimeQualityConfigurationListDto> response =
                timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(0, response.getTotalItems());
        Assertions.assertTrue(response.getItems().isEmpty());
    }

    @Test
    void testListTimeQualityConfigurations_multipleEntries() throws AlreadyExistException, AttributeException, NotFoundException {
        timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("config-alpha"));
        timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("config-beta"));

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<TimeQualityConfigurationListDto> response =
                timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());

        Assertions.assertEquals(3, response.getTotalItems());
        List<String> names = response.getItems().stream().map(TimeQualityConfigurationListDto::getName).toList();
        Assertions.assertTrue(names.contains("existing-tq-config"));
        Assertions.assertTrue(names.contains("config-alpha"));
        Assertions.assertTrue(names.contains("config-beta"));
    }

    @Test
    void testListTimeQualityConfigurations_paginationMetadataIsCorrect() throws AlreadyExistException, AttributeException, NotFoundException {
        timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("config-page-1"));
        timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("config-page-2"));

        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(2);
        PaginationResponseDto<TimeQualityConfigurationListDto> response =
                timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());

        Assertions.assertEquals(1, response.getPageNumber());
        Assertions.assertEquals(2, response.getItemsPerPage());
        Assertions.assertEquals(3, response.getTotalItems());
        Assertions.assertEquals(2, response.getTotalPages());
        Assertions.assertEquals(2, response.getItems().size());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testGetTimeQualityConfiguration_returnsCorrectDto() throws NotFoundException {
        TimeQualityConfigurationDto dto = timeQualityConfigurationService.getTimeQualityConfiguration(savedConfiguration.getSecuredUuid());

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedConfiguration.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals("existing-tq-config", dto.getName());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getAccuracy());
        Assertions.assertEquals(List.of("pool.ntp.org"), dto.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(30), dto.getNtpCheckInterval());
        Assertions.assertEquals(4, dto.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(5), dto.getNtpCheckTimeout());
        Assertions.assertEquals(1, dto.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getMaxClockDrift());
        Assertions.assertTrue(dto.isLeapSecondGuard());
    }

    @Test
    void testGetTimeQualityConfiguration_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> timeQualityConfigurationService.getTimeQualityConfiguration(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTimeQualityConfiguration_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildCreateRequest("new-tq-config");

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.createTimeQualityConfiguration(request);

        // Assert returned DTO
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());
        Assertions.assertEquals("new-tq-config", dto.getName());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getAccuracy());
        Assertions.assertEquals(List.of("pool.ntp.org", "time.google.com"), dto.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(30), dto.getNtpCheckInterval());
        Assertions.assertEquals(4, dto.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(5), dto.getNtpCheckTimeout());
        Assertions.assertEquals(1, dto.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getMaxClockDrift());
        Assertions.assertTrue(dto.isLeapSecondGuard());

        // Assert entity reloaded from the database
        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        TimeQualityConfiguration entity = fromDb.get();
        Assertions.assertEquals("new-tq-config", entity.getName());
        Assertions.assertEquals(Duration.ofSeconds(1), entity.getAccuracy());
        Assertions.assertEquals(List.of("pool.ntp.org", "time.google.com"), entity.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(30), entity.getNtpCheckInterval());
        Assertions.assertEquals(4, entity.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(5), entity.getNtpCheckTimeout());
        Assertions.assertEquals(1, entity.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofSeconds(1), entity.getMaxClockDrift());
        Assertions.assertTrue(entity.getLeapSecondGuard());
    }

    @Test
    void testCreateTimeQualityConfiguration_withLeapSecondGuardFalse_assertDtoAndDbEntity()
            throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildCreateRequest("no-leap-guard");
        request.setLeapSecondGuard(false);

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.createTimeQualityConfiguration(request);

        Assertions.assertFalse(dto.isLeapSecondGuard());

        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertFalse(fromDb.get().getLeapSecondGuard());
    }

    @Test
    void testCreateTimeQualityConfiguration_multipleNtpServers_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildCreateRequest("multi-ntp");
        request.setNtpServers(List.of("ntp1.example.com", "ntp2.example.com", "ntp3.example.com"));

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.createTimeQualityConfiguration(request);

        Assertions.assertEquals(3, dto.getNtpServers().size());
        Assertions.assertTrue(dto.getNtpServers().contains("ntp1.example.com"));
        Assertions.assertTrue(dto.getNtpServers().contains("ntp2.example.com"));
        Assertions.assertTrue(dto.getNtpServers().contains("ntp3.example.com"));

        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(3, fromDb.get().getNtpServers().size());
    }

    @Test
    void testCreateTimeQualityConfiguration_customAccuracyAndDrift_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildCreateRequest("custom-accuracy");
        request.setAccuracy(Duration.ofMillis(100));
        request.setMaxClockDrift(Duration.ofMillis(200));

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.createTimeQualityConfiguration(request);

        Assertions.assertEquals(Duration.ofMillis(100), dto.getAccuracy());
        Assertions.assertEquals(Duration.ofMillis(200), dto.getMaxClockDrift());

        Optional<TimeQualityConfiguration> fromDb = timeQualityConfigurationRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(Duration.ofMillis(100), fromDb.get().getAccuracy());
        Assertions.assertEquals(Duration.ofMillis(200), fromDb.get().getMaxClockDrift());
    }

    @Test
    void testCreateTimeQualityConfiguration_duplicateName_throwsAlreadyExistException() throws AlreadyExistException, AttributeException, NotFoundException {
        timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("duplicate-name"));
        Assertions.assertThrows(AlreadyExistException.class,
                () -> timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("duplicate-name")));
    }

    @Test
    void create_translatesDbUniqueViolationToAlreadyExist() {
        Mockito.doReturn(Optional.empty()).when(timeQualityConfigurationRepository).findByName("race-name");
        Mockito.doThrow(new DataIntegrityViolationException("unique constraint violation"))
               .when(timeQualityConfigurationRepository).saveAndFlush(any(TimeQualityConfiguration.class));

        AlreadyExistException ex = Assertions.assertThrows(AlreadyExistException.class,
                () -> timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("race-name")));
        Assertions.assertTrue(ex.getMessage().contains("race-name"));
    }

    @Test
    void update_translatesDbUniqueViolationToAlreadyExist() {
        Mockito.doReturn(Optional.empty()).when(timeQualityConfigurationRepository).findByName("race-name");
        Mockito.doThrow(new DataIntegrityViolationException("unique constraint violation"))
               .when(timeQualityConfigurationRepository).saveAndFlush(any(TimeQualityConfiguration.class));

        AlreadyExistException ex = Assertions.assertThrows(AlreadyExistException.class,
                () -> timeQualityConfigurationService.updateTimeQualityConfiguration(
                        savedConfiguration.getSecuredUuid(), buildUpdateRequest("race-name")));
        Assertions.assertTrue(ex.getMessage().contains("race-name"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Update
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testUpdateTimeQualityConfiguration_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildUpdateRequest("updated-tq-config");

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.updateTimeQualityConfiguration(
                savedConfiguration.getSecuredUuid(), request);

        // Assert returned DTO
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedConfiguration.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals("updated-tq-config", dto.getName());
        Assertions.assertEquals(Duration.ofMillis(500), dto.getAccuracy());
        Assertions.assertEquals(List.of("time.cloudflare.com"), dto.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(60), dto.getNtpCheckInterval());
        Assertions.assertEquals(8, dto.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(10), dto.getNtpCheckTimeout());
        Assertions.assertEquals(2, dto.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofMillis(500), dto.getMaxClockDrift());
        Assertions.assertFalse(dto.isLeapSecondGuard());

        // Assert entity reloaded from the database
        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(savedConfiguration.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        TimeQualityConfiguration entity = fromDb.get();
        Assertions.assertEquals("updated-tq-config", entity.getName());
        Assertions.assertEquals(Duration.ofMillis(500), entity.getAccuracy());
        Assertions.assertEquals(List.of("time.cloudflare.com"), entity.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(60), entity.getNtpCheckInterval());
        Assertions.assertEquals(8, entity.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(10), entity.getNtpCheckTimeout());
        Assertions.assertEquals(2, entity.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofMillis(500), entity.getMaxClockDrift());
        Assertions.assertFalse(entity.getLeapSecondGuard());
    }

    @Test
    void testUpdateTimeQualityConfiguration_notFound_throwsNotFoundException() {
        TimeQualityConfigurationRequestDto request = buildUpdateRequest("does-not-matter");

        Assertions.assertThrows(NotFoundException.class,
                () -> timeQualityConfigurationService.updateTimeQualityConfiguration(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"), request));
    }

    @Test
    void testUpdateTimeQualityConfiguration_preservesUuid() throws AlreadyExistException, AttributeException, NotFoundException {
        UUID originalUuid = savedConfiguration.getUuid();

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.updateTimeQualityConfiguration(
                savedConfiguration.getSecuredUuid(), buildUpdateRequest("renamed-config"));

        Assertions.assertEquals(originalUuid.toString(), dto.getUuid());
        Optional<TimeQualityConfiguration> fromDb = timeQualityConfigurationRepository.findById(originalUuid);
        Assertions.assertTrue(fromDb.isPresent());
    }

    @Test
    void testUpdateTimeQualityConfiguration_ntpServersReplaced_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationRequestDto request = buildUpdateRequest("servers-replaced");
        request.setNtpServers(List.of("ntp-a.example.com", "ntp-b.example.com"));

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.updateTimeQualityConfiguration(
                savedConfiguration.getSecuredUuid(), request);

        Assertions.assertEquals(2, dto.getNtpServers().size());
        Assertions.assertTrue(dto.getNtpServers().contains("ntp-a.example.com"));
        Assertions.assertFalse(dto.getNtpServers().contains("pool.ntp.org"),
                "Original NTP server should be replaced after update");

        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(savedConfiguration.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(List.of("ntp-a.example.com", "ntp-b.example.com"), fromDb.get().getNtpServers());
    }

    @Test
    void testUpdateTimeQualityConfiguration_toExistingNameOfAnotherConfig_throwsAlreadyExistException() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationDto second = timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("config-beta"));
        TimeQualityConfigurationRequestDto updateRequest = buildUpdateRequest("existing-tq-config");
        Assertions.assertThrows(AlreadyExistException.class,
                () -> timeQualityConfigurationService.updateTimeQualityConfiguration(SecuredUUID.fromString(second.getUuid()), updateRequest));
    }

    @Test
    void testUpdateTimeQualityConfiguration_keepingSameName_succeeds() throws AlreadyExistException, NotFoundException, AttributeException {
        TimeQualityConfigurationRequestDto updateRequest = buildUpdateRequest("existing-tq-config");
        updateRequest.setNtpSamplesPerServer(8);
        TimeQualityConfigurationDto updated = timeQualityConfigurationService.updateTimeQualityConfiguration(
                savedConfiguration.getSecuredUuid(), updateRequest);
        Assertions.assertEquals("existing-tq-config", updated.getName());
        Assertions.assertEquals(8, updated.getNtpSamplesPerServer());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testDeleteTimeQualityConfiguration_removesEntity() throws NotFoundException {
        timeQualityConfigurationService.deleteTimeQualityConfiguration(savedConfiguration.getSecuredUuid());

        Optional<TimeQualityConfiguration> fromDb =
                timeQualityConfigurationRepository.findById(savedConfiguration.getUuid());
        Assertions.assertTrue(fromDb.isEmpty(), "Entity should be removed from the database after deletion");
    }

    @Test
    void testDeleteTimeQualityConfiguration_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> timeQualityConfigurationService.deleteTimeQualityConfiguration(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Bulk Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testBulkDeleteTimeQualityConfigurations_deletesAll() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationDto second = timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("bulk-delete-second"));

        List<BulkActionMessageDto> messages = timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(
                List.of(savedConfiguration.getSecuredUuid(), SecuredUUID.fromString(second.getUuid())));

        Assertions.assertTrue(messages.isEmpty(), "No error messages expected when all deletions succeed");
        Assertions.assertEquals(0, timeQualityConfigurationRepository.count());
    }

    @Test
    void testBulkDeleteTimeQualityConfigurations_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

        List<BulkActionMessageDto> messages = timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(
                List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000099", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDelete_partialFailure_survivingItemsAreCommitted() throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationDto second = timeQualityConfigurationService.createTimeQualityConfiguration(buildCreateRequest("bulk-partial-second"));
        UUID secondUuid = UUID.fromString(second.getUuid());

        // Throw a RuntimeException for the first item only, keyed by its UUID.
        // AttributeEngine is a concrete class so doCallRealMethod() works for the second item.
        Mockito.doThrow(new DataIntegrityViolationException("simulated FK violation"))
               .when(attributeEngine).deleteObjectAttributeContent(Resource.TIME_QUALITY_CONFIGURATION, savedConfiguration.getUuid());

        List<BulkActionMessageDto> messages = timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(
                List.of(savedConfiguration.getSecuredUuid(), SecuredUUID.fromString(second.getUuid())));

        Assertions.assertEquals(1, messages.size(), "Only the failing item should produce an error message");
        Assertions.assertEquals(savedConfiguration.getUuid().toString(), messages.getFirst().getUuid());

        Assertions.assertTrue(timeQualityConfigurationRepository.findById(savedConfiguration.getUuid()).isPresent(),
                "Failed item's REQUIRES_NEW transaction should have been rolled back, leaving the entity in the DB");
        Assertions.assertTrue(timeQualityConfigurationRepository.findById(secondUuid).isEmpty(),
                "Successful item's REQUIRES_NEW transaction should have committed independently");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Custom attributes
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateTimeQualityConfiguration_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("tq-value-on-create")));

        TimeQualityConfigurationRequestDto request = buildCreateRequest("tq-with-custom-attr");
        request.setCustomAttributes(List.of(customAttr));

        TimeQualityConfigurationDto dto = timeQualityConfigurationService.createTimeQualityConfiguration(request);

        Assertions.assertNotNull(dto.getCustomAttributes());
        Assertions.assertFalse(dto.getCustomAttributes().isEmpty(),
                "Custom attributes should be returned in the create DTO");
        Assertions.assertEquals("tq-value-on-create",
                ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    @Test
    void testUpdateTimeQualityConfiguration_withCustomAttributes_returnedInDto()
            throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 createAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("initial-value")));
        TimeQualityConfigurationRequestDto createRequest = buildCreateRequest("tq-update-custom-attr");
        createRequest.setCustomAttributes(List.of(createAttr));
        TimeQualityConfigurationDto created = timeQualityConfigurationService.createTimeQualityConfiguration(createRequest);

        RequestAttributeV3 updateAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("updated-value")));
        TimeQualityConfigurationRequestDto updateRequest = buildUpdateRequest("tq-update-custom-attr");
        updateRequest.setCustomAttributes(List.of(updateAttr));
        TimeQualityConfigurationDto updated = timeQualityConfigurationService.updateTimeQualityConfiguration(
                SecuredUUID.fromString(created.getUuid()), updateRequest);

        Assertions.assertNotNull(updated.getCustomAttributes());
        Assertions.assertFalse(updated.getCustomAttributes().isEmpty());
        Assertions.assertEquals("updated-value",
                ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    @Test
    void testGetTimeQualityConfiguration_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("get-test-value")));

        TimeQualityConfigurationRequestDto createRequest = buildCreateRequest("tq-get-custom-attr");
        createRequest.setCustomAttributes(List.of(customAttr));
        TimeQualityConfigurationDto created = timeQualityConfigurationService.createTimeQualityConfiguration(createRequest);

        TimeQualityConfigurationDto fetched = timeQualityConfigurationService.getTimeQualityConfiguration(
                SecuredUUID.fromString(created.getUuid()));

        Assertions.assertNotNull(fetched.getCustomAttributes());
        Assertions.assertFalse(fetched.getCustomAttributes().isEmpty(),
                "Custom attributes should be returned in the get DTO");
        Assertions.assertEquals("get-test-value",
                ((ResponseAttributeV3) fetched.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    @Test
    void testDeleteTimeQualityConfiguration_customAttributesAreRemoved() throws AlreadyExistException, AttributeException, NotFoundException {
        RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("to-be-deleted-value")));

        TimeQualityConfigurationRequestDto createRequest = buildCreateRequest("tq-delete-custom-attr");
        createRequest.setCustomAttributes(List.of(customAttr));
        TimeQualityConfigurationDto created = timeQualityConfigurationService.createTimeQualityConfiguration(createRequest);

        SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
        timeQualityConfigurationService.deleteTimeQualityConfiguration(uuid);

        Assertions.assertTrue(timeQualityConfigurationRepository.findById(UUID.fromString(created.getUuid())).isEmpty(),
                "Configuration should be deleted from the repository");
    }
}
