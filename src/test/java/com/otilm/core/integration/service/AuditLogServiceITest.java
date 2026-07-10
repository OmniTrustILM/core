package com.otilm.core.integration.service;

import com.otilm.api.interfaces.core.web.AuditLogController;
import com.otilm.api.interfaces.core.web.SettingController;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.audit.ExportResultDto;
import com.otilm.api.model.core.logging.enums.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.messaging.jms.listeners.AuditLogsListener;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.Resource;
import com.otilm.core.service.AuditLogExternalService;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.io.FileOutputStream;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

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
    void testExportAuditLog() {
        auditLogController.listAuditLogs(new SearchRequestDto());
        settingController.getPlatformSettings();

        AuditLog auditLog = new AuditLog();
        auditLog.setLogRecord(LogRecord.builder()
                .resource(ResourceRecord.builder()
                        .objects(List.of(new ResourceObjectIdentity("name", UUID.randomUUID()))).build())
                .affiliatedResource(ResourceRecord.builder()
                        .objects(List.of(new ResourceObjectIdentity("name", UUID.randomUUID()))).build())
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
        LogRecord logRecord = LogRecord.builder()
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
