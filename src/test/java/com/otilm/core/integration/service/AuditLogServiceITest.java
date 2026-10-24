package com.otilm.core.integration.service;

import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.otilm.api.interfaces.core.web.AuditLogController;
import com.otilm.api.interfaces.core.web.SettingController;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.audit.ExportResultDto;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.messaging.jms.listeners.AuditLogsListener;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.Resource;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.AuditLogExternalService;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class AuditLogServiceITest extends BaseSpringBootTest {

    @Autowired
    private AuditLogExternalService auditLogService;

    @Autowired
    private AuditLogInternalService auditLogInternalService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SettingController settingController;

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private AuditLogController auditLogController;

    @Autowired
    private AuditLogsListener auditLogsListener;

    @BeforeEach
    public void setUp() {
        Mockito.doAnswer(invocation -> {
            Object msg = invocation.getArgument(0);
            auditLogsListener.processMessage((AuditLogMessage) msg);
            return null; // because produceMessage returns void
        }).when(auditLogsProducer).produceMessage(Mockito.any());

        LoggingSettingsDto loggingSettingsDto = new LoggingSettingsDto();

        AuditLoggingSettingsDto auditLoggingSettingsDto = new AuditLoggingSettingsDto();
        auditLoggingSettingsDto.setOutput(AuditLogOutput.ALL);
        auditLoggingSettingsDto.setLogAllModules(true);
        auditLoggingSettingsDto.setLogAllResources(true);
        loggingSettingsDto.setAuditLogs(auditLoggingSettingsDto);

        ResourceLoggingSettingsDto eventLoggingSettingsDto = new ResourceLoggingSettingsDto();
        eventLoggingSettingsDto.setLogAllModules(true);
        eventLoggingSettingsDto.setLogAllResources(true);
        loggingSettingsDto.setEventLogs(eventLoggingSettingsDto);

        settingService.updateLoggingSettings(loggingSettingsDto);
    }

    @Test
    void searchableResourceFieldsOfferNoWildcardsARecordCannotCarry() {
        List<SearchFieldDataDto> fields = auditLogService
                .getSearchableFieldInformationByGroup()
                .stream()
                .flatMap(group -> group.getSearchFieldData().stream())
                .toList();

        assertThat(codesOffered(fields, FilterField.AUDIT_LOG_RESOURCE))
                .contains("NONE", "certificates")
                .doesNotContain("ANY");
        assertThat(codesOffered(fields, FilterField.AUDIT_LOG_AFFILIATED_RESOURCE))
                .contains("certificates")
                .doesNotContain("NONE", "ANY");
    }

    @SuppressWarnings("unchecked")
    private static List<String> codesOffered(List<SearchFieldDataDto> fields, FilterField field) {
        return (List<String>) fields
                .stream()
                .filter(candidate -> field.name().equals(candidate.getFieldIdentifier()))
                .findFirst()
                .orElseThrow()
                .getValue();
    }

    @Test
    void filtersStoredDelegatesWithoutChangingTheUserOrMatchingDirectRecords() {
        storeAuditRecord("1.1", null);
        storeAuditRecord("1.2", null);
        storeAuditRecord("1.2", new DelegateRecord("another-client", "another-subject"));
        AuditLog delegated = storeAuditRecord("1.2", new DelegateRecord("automation-client", "service-account-id"));

        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(delegateFilter("automation-client")));
        var result = auditLogService.listAuditLogs(request);

        assertThat(result.getTotalItems()).isEqualTo(1);
        assertThat(result.getItems()).singleElement().satisfies(auditRecord -> {
            assertThat(auditRecord.getId()).isEqualTo(delegated.getId());
            assertThat(auditRecord.getActor().name()).isEqualTo("alice");
            assertThat(auditRecord.getActor().delegate())
                    .isEqualTo(new DelegateRecord("automation-client", "service-account-id"));
        });
        assertThat(auditLogService.listAuditLogs(new SearchRequestDto()).getTotalItems()).isEqualTo(4);
    }

    @Test
    void offersTheDelegateFilterToTheAdministrator() {
        assertThat(auditLogService.getSearchableFieldInformationByGroup())
                .flatExtracting(group -> group.getSearchFieldData())
                .filteredOn(field -> "AUDIT_LOG_ACTOR_DELEGATE_IDENTIFIER".equals(field.getFieldIdentifier()))
                .singleElement()
                .satisfies(field -> assertThat(field.getFieldLabel()).isEqualTo("Delegate"));
    }

    @Test
    void exportsDelegateColumnsAndLeavesThemEmptyForDirectAndLegacyRecords() throws IOException {
        AuditLog legacy = storeAuditRecord("1.1", null);
        AuditLog direct = storeAuditRecord("1.2", null);
        AuditLog delegated = storeAuditRecord("1.2", new DelegateRecord("automation-client", "service-account-id"));
        AuditLog noSubject = storeAuditRecord("1.2", new DelegateRecord("client-without-subject", null));

        List<Map<String, String>> rows = readCsv(auditLogService.exportAuditLogs(List.of()));

        assertThat(rows).hasSize(4);
        assertThat(rowById(rows, delegated.getId()))
                .containsEntry("actorName", "alice")
                .containsEntry("actorDelegateIdentifier", "automation-client")
                .containsEntry("actorDelegateSubject", "service-account-id");
        assertThat(rowById(rows, noSubject.getId()))
                .containsEntry("actorDelegateIdentifier", "client-without-subject")
                .containsEntry("actorDelegateSubject", "");
        for (AuditLog ordinary : List.of(legacy, direct)) {
            assertThat(rowById(rows, ordinary.getId()))
                    .containsEntry("actorName", "alice")
                    .containsEntry("actorDelegateIdentifier", "")
                    .containsEntry("actorDelegateSubject", "");
        }

        assertThat(readCsv(auditLogService.exportAuditLogs(List.of(delegateFilter("automation-client")))))
                .singleElement()
                .satisfies(row -> assertThat(row).containsEntry("id", delegated.getId().toString()));
    }

    private AuditLog storeAuditRecord(String version, DelegateRecord delegate) {
        LogRecord auditRecord = LogRecord
                .builder()
                .version(version)
                .audited(true)
                .timestamp(OffsetDateTime.parse("2026-10-24T10:15:30Z"))
                .module(Module.AUTH)
                .actor(new ActorRecord(ActorType.USER, AuthMethod.TOKEN,
                        UUID.fromString("b2cba93a-7cd6-4a2f-a050-6631c3886059"), "alice", delegate))
                .resource(new ResourceRecord(com.otilm.api.model.core.auth.Resource.USER, List.of()))
                .operation(Operation.DETAIL)
                .operationResult(OperationResult.SUCCESS)
                .build();
        return auditLogRepository.saveAndFlush(AuditLog.fromLogRecord(auditRecord));
    }

    private static SearchFilterRequestDto delegateFilter(String identifier) {
        SearchFilterRequestDto filter = new SearchFilterRequestDto();
        filter.setFieldSource(FilterFieldSource.PROPERTY);
        filter.setCondition(FilterConditionOperator.EQUALS);
        filter.setFieldIdentifier("AUDIT_LOG_ACTOR_DELEGATE_IDENTIFIER");
        filter.setValue(identifier);
        return filter;
    }

    private static List<Map<String, String>> readCsv(ExportResultDto result) throws IOException {
        byte[] content = result.getFileContent();
        if (result.getFileName().endsWith(".zip")) {
            try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(content))) {
                assertThat(zip.getNextEntry()).isNotNull();
                content = zip.readAllBytes();
            }
        }
        return ObjectMapperFactory
                .csvExport()
                .readerFor(Map.class)
                .with(CsvSchema.emptySchema().withHeader())
                .<Map<String, String>>readValues(content)
                .readAll();
    }

    private static Map<String, String> rowById(List<Map<String, String>> rows, Long id) {
        return rows.stream().filter(row -> id.toString().equals(row.get("id"))).findFirst().orElseThrow();
    }

    @Test
    void testExportAuditLog() {
        auditLogController.listAuditLogs(new SearchRequestDto());
        settingController.getPlatformSettings();

        AuditLog auditLog = new AuditLog();
        auditLog
                .setLogRecord(LogRecord
                        .builder()
                        .resource(ResourceRecord
                                .builder()
                                .objects(List.of(new ResourceObjectIdentity("name", UUID.randomUUID())))
                                .build())
                        .affiliatedResource(ResourceRecord
                                .builder()
                                .objects(List.of(new ResourceObjectIdentity("name", UUID.randomUUID())))
                                .build())
                        .build());
        auditLog.setTimestamp(OffsetDateTime.now());
        auditLog.setLoggedAt(OffsetDateTime.now());
        auditLog.setModule(Module.AUTH);
        auditLog.setActorAuthMethod(AuthMethod.NONE);
        auditLog.setActorType(ActorType.CORE);
        auditLog.setResource(com.otilm.api.model.core.auth.Resource.CERTIFICATE);
        auditLog.setAffiliatedResource(com.otilm.api.model.core.auth.Resource.AUDIT_LOG);
        auditLog.setVersion("1");
        auditLog.setOperation(Operation.LOGOUT);
        auditLog.setOperationResult(OperationResult.SUCCESS);
        auditLogRepository.save(auditLog);
        ExportResultDto result = auditLogService.exportAuditLogs(List.of());

        Assertions.assertDoesNotThrow(() -> {
            try (FileOutputStream fos = new FileOutputStream(File.createTempFile(result.getFileName(), ""))) {
                fos.write(result.getFileContent());
                fos.flush();
            }
        });
    }

    @Test
    void testLogWithOutput() {
        LogRecord logRecord = LogRecord
                .builder()
                .actor(ActorRecord.builder().authMethod(AuthMethod.CERTIFICATE).type(ActorType.USER).build())
                .resource(ResourceRecord.builder().type(com.otilm.api.model.core.auth.Resource.USER).build())
                .timestamp(OffsetDateTime.now())
                .module(Module.AUTH)
                .version("1")
                .operation(Operation.LOGOUT)
                .operationResult(OperationResult.SUCCESS)
                .build();
        Assertions.assertDoesNotThrow(() -> auditLogInternalService.log(logRecord, null));
        Assertions.assertDoesNotThrow(() -> auditLogInternalService.log(logRecord, AuditLogOutput.CONSOLE));
        Assertions.assertDoesNotThrow(() -> auditLogInternalService.log(logRecord, AuditLogOutput.DATABASE));
        Assertions.assertDoesNotThrow(() -> auditLogInternalService.log(logRecord, AuditLogOutput.ALL));
        Assertions.assertDoesNotThrow(() -> auditLogInternalService.log(logRecord, AuditLogOutput.NONE));
    }

    @Test
    void testPurgeAuditLogs() {

        auditLogController.listAuditLogs(new SearchRequestDto());
        auditLogController.listAuditLogs(new SearchRequestDto());
        auditLogController.listAuditLogs(new SearchRequestDto());
        settingController.getLoggingSettings();
        settingController.getPlatformSettings();

        Assertions.assertEquals(5, auditLogRepository.findAll().size());

        SearchFilterRequestDto searchFilter = new SearchFilterRequestDto();
        searchFilter.setFieldSource(FilterFieldSource.PROPERTY);
        searchFilter.setCondition(FilterConditionOperator.EQUALS);
        searchFilter.setFieldIdentifier(FilterField.AUDIT_LOG_RESOURCE.toString());
        searchFilter.setValue(Resource.SETTINGS.getCode());
        auditLogService.purgeAuditLogs(List.of(searchFilter));

        Assertions.assertEquals(3, auditLogRepository.findAll().size());

        auditLogService.purgeAuditLogs(List.of());

        // we expect 0 record to be available after purging all because only controller is annotated to do audit logging
        Assertions.assertEquals(0, auditLogRepository.findAll().size());
    }
}
