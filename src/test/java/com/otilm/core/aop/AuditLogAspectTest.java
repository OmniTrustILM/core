package com.otilm.core.aop;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.interfaces.core.web.SettingController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.jms.listeners.AuditLogsListener;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

class AuditLogAspectTest extends BaseSpringBootTest {

    /**
     * Minimal bean that demonstrates the AuditResultOverride contract: the method swallows an
     * exception internally (like the TSP controller does) and signals audit failure via the override
     * instead of throwing past the aspect.
     */
    @TestConfiguration
    static class Config {
        @Bean
        SwallowsAndOverridesBean swallowsAndOverridesBean() {
            return new SwallowsAndOverridesBean();
        }
    }

    static class SwallowsAndOverridesBean {
        @Autowired
        private AuditResultOverride auditResultOverride;

        @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SIGNING_RECORD, operation = Operation.SIGN)
        public void performAndSignalFailure() {
            auditResultOverride.setFailure();
        }

        @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SIGNING_RECORD, operation = Operation.SIGN)
        public void performAndSucceed() {
            // no override — aspect must record SUCCESS
        }
    }

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SettingController settingController;

    @Autowired
    private CryptographicKeyController keyController;

    @Autowired
    private SwallowsAndOverridesBean swallowsAndOverridesBean;

    @Autowired
    private AuditLogsListener auditLogsListener;

    @Test
    void testListKeyPairsAudit() throws ConnectorException {
        Mockito.doAnswer(invocation -> {
            Object msg = invocation.getArgument(0);
            auditLogsListener.processMessage((AuditLogMessage) msg);
            return null; // because produceMessage returns void
        }).when(auditLogsProducer).produceMessage(Mockito.any());

        keyController.listKeyPairs(Optional.empty());
        List<AuditLog> auditLogs = auditLogRepository.findAll();

        Assertions.assertThrows(NotFoundException.class, () -> keyController.destroyKey(UUID.randomUUID().toString(), null));
        Assertions.assertThrows(NotFoundException.class, () -> keyController.compromiseKey(UUID.randomUUID().toString(), null));
        Assertions.assertEquals(0, auditLogs.size());

        turnOnLogging();

        keyController.listKeyPairs(Optional.empty());
        keyController.listKeyPairs(Optional.ofNullable(UUID.randomUUID().toString()));
        Assertions.assertThrows(NotFoundException.class, () -> keyController.listCreateKeyAttributes(UUID.randomUUID().toString(), UUID.randomUUID().toString(), KeyRequestType.KEY_PAIR));
        keyController.deleteKeys(List.of(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        settingController.getLoggingSettings();
        BulkCompromiseKeyRequestDto bulkCompromiseKeyRequestDto = new BulkCompromiseKeyRequestDto();
        bulkCompromiseKeyRequestDto.setUuids(List.of(UUID.randomUUID(), UUID.randomUUID()));
        keyController.compromiseKeys(bulkCompromiseKeyRequestDto);

        // Simulate retrieving data from MDC
        UUID resourceUuid = UUID.randomUUID();
        String resourceName = "name";
        LoggingHelper.putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY, false, String.valueOf(resourceUuid), resourceName);
        keyController.listCryptographicKeys(new SearchRequestDto());

        auditLogs = auditLogRepository.findAll();
        Assertions.assertEquals(7, auditLogs.size());

        AuditLog auditLogNoUuidResource = auditLogs.getFirst();
        Assertions.assertEquals(Resource.TOKEN_PROFILE, auditLogNoUuidResource.getLogRecord().affiliatedResource().type());
        Assertions.assertNull(auditLogNoUuidResource.getLogRecord().affiliatedResource().objects());

        AuditLog auditLogWithUuidResource = auditLogs.get(1);
        Assertions.assertEquals(Resource.TOKEN_PROFILE, auditLogWithUuidResource.getLogRecord().affiliatedResource().type());
        Assertions.assertEquals(1, auditLogWithUuidResource.getLogRecord().affiliatedResource().objects().size());

        AuditLog auditLogWithNamedResource = auditLogs.get(2);
        Assertions.assertEquals(OperationResult.FAILURE, auditLogWithNamedResource.getOperationResult());
        Assertions.assertEquals(Resource.ATTRIBUTE, auditLogWithNamedResource.getLogRecord().resource().type());
        Assertions.assertEquals(KeyRequestType.KEY_PAIR.getCode(), auditLogWithNamedResource.getLogRecord().resource().objects().getFirst().name());

        AuditLog auditLogWithMoreUuidResource = auditLogs.get(3);
        Assertions.assertEquals(Resource.CRYPTOGRAPHIC_KEY, auditLogWithMoreUuidResource.getLogRecord().resource().type());
        Assertions.assertEquals(2, auditLogWithMoreUuidResource.getLogRecord().resource().objects().size());

        AuditLog auditLogWithNamedResourceDirectly = auditLogs.get(4);
        Assertions.assertEquals(Resource.SETTINGS, auditLogWithNamedResourceDirectly.getLogRecord().resource().type());
        Assertions.assertEquals(SettingsSection.LOGGING.getCode(), auditLogWithNamedResourceDirectly.getLogRecord().resource().objects().getFirst().name());

        AuditLog auditLogWithUuidsFromRequest = auditLogs.get(5);
        Assertions.assertEquals(2, auditLogWithUuidsFromRequest.getLogRecord().resource().objects().size());

        AuditLog auditLogFromMdc = auditLogs.get(6);
        Assertions.assertEquals(Resource.CRYPTOGRAPHIC_KEY, auditLogFromMdc.getLogRecord().resource().type());
        Assertions.assertEquals(1, auditLogFromMdc.getLogRecord().resource().objects().size());
        Assertions.assertEquals(resourceName, auditLogFromMdc.getLogRecord().resource().objects().getFirst().name());
        Assertions.assertEquals(resourceUuid, auditLogFromMdc.getLogRecord().resource().objects().getFirst().uuid());

        // Test that the audit log aspect does not throw error for empty list of UUIDs on the input
        Assertions.assertDoesNotThrow(() -> keyController.enableKeys(List.of()));

    }

    @Test
    void auditResultOverride_auditsOperationAsFailure_whenMethodSwallowsExceptionAndSetsOverride() {
        // given
        Mockito.doAnswer(invocation -> {
            auditLogsListener.processMessage(invocation.getArgument(0));
            return null;
        }).when(auditLogsProducer).produceMessage(Mockito.any());
        turnOnLogging();

        // when — method returns normally but has set the override (simulates TSP rejection pattern)
        runInRequestScope(swallowsAndOverridesBean::performAndSignalFailure);

        // then
        List<AuditLog> auditLogs = auditLogRepository.findAll();
        Assertions.assertEquals(1, auditLogs.size());
        Assertions.assertEquals(OperationResult.FAILURE, auditLogs.getFirst().getOperationResult());
    }

    @Test
    void auditResultOverride_auditsOperationAsSuccess_whenNoOverrideSet() {
        // given
        Mockito.doAnswer(invocation -> {
            auditLogsListener.processMessage(invocation.getArgument(0));
            return null;
        }).when(auditLogsProducer).produceMessage(Mockito.any());
        turnOnLogging();

        // when
        runInRequestScope(swallowsAndOverridesBean::performAndSucceed);

        // then
        List<AuditLog> auditLogs = auditLogRepository.findAll();
        Assertions.assertEquals(1, auditLogs.size());
        Assertions.assertEquals(OperationResult.SUCCESS, auditLogs.getFirst().getOperationResult());
    }

    /**
     * Binds a request scope around the action so the request-scoped {@link AuditResultOverride}
     * resolves — production audited methods always run inside a DispatcherServlet request, but the
     * test invokes the bean directly.
     */
    private void runInRequestScope(Runnable action) {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        try {
            action.run();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private void turnOnLogging() {
        LoggingSettingsDto loggingSettingsDto = new LoggingSettingsDto();

        AuditLoggingSettingsDto auditLoggingSettingsDto = new AuditLoggingSettingsDto();
        auditLoggingSettingsDto.setOutput(AuditLogOutput.ALL);
        auditLoggingSettingsDto.setLogAllModules(true);
        auditLoggingSettingsDto.setLogAllResources(true);
        auditLoggingSettingsDto.setVerbose(true);
        loggingSettingsDto.setAuditLogs(auditLoggingSettingsDto);

        ResourceLoggingSettingsDto eventLoggingSettingsDto = new ResourceLoggingSettingsDto();
        eventLoggingSettingsDto.setLogAllModules(true);
        eventLoggingSettingsDto.setLogAllResources(true);
        loggingSettingsDto.setEventLogs(eventLoggingSettingsDto);

        settingService.updateLoggingSettings(loggingSettingsDto);
    }

}
