package com.czertainly.core.service;

import com.czertainly.api.interfaces.core.web.AuditLogController;
import com.czertainly.api.interfaces.core.web.SettingController;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.core.audit.ExportResultDto;
import com.czertainly.api.model.core.logging.enums.*;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.records.ActorRecord;
import com.czertainly.api.model.core.logging.records.LogRecord;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.api.model.core.logging.records.ResourceRecord;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.czertainly.api.model.core.settings.logging.LoggingSettingsDto;
import com.czertainly.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.czertainly.core.dao.entity.AuditLog;
import com.czertainly.core.dao.repository.AuditLogRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.messaging.jms.listeners.AuditLogsListener;
import com.czertainly.core.messaging.jms.producers.AuditLogsProducer;
import com.czertainly.core.messaging.model.AuditLogMessage;
import com.czertainly.core.model.auth.Resource;
import com.czertainly.core.util.BaseSpringBootTest;
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
class AuditLogServiceTest extends BaseSpringBootTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SettingController settingController;

    @Autowired
    private SettingService settingService;

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
        auditLog.setResource(com.czertainly.api.model.core.auth.Resource.CERTIFICATE);
        auditLog.setAffiliatedResource(com.czertainly.api.model.core.auth.Resource.AUDIT_LOG);
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
                .resource(ResourceRecord.builder().type(com.czertainly.api.model.core.auth.Resource.USER).build())
                .timestamp(OffsetDateTime.now())
                .module(Module.AUTH)
                .version("1")
                .operation(Operation.LOGOUT)
                .operationResult(OperationResult.SUCCESS)
                .build();
        Assertions.assertDoesNotThrow(() -> auditLogService.log(logRecord, null));
        Assertions.assertDoesNotThrow(() -> auditLogService.log(logRecord, AuditLogOutput.CONSOLE));
        Assertions.assertDoesNotThrow(() -> auditLogService.log(logRecord, AuditLogOutput.DATABASE));
        Assertions.assertDoesNotThrow(() -> auditLogService.log(logRecord, AuditLogOutput.ALL));
        Assertions.assertDoesNotThrow(() -> auditLogService.log(logRecord, AuditLogOutput.NONE));
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
