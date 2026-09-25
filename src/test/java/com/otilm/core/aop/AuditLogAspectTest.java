package com.otilm.core.aop;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.logging.AuditLogEnhancer;
import com.otilm.core.messaging.jms.producers.AuditLogsProducer;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import java.util.Map;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuditLogAspectTest {

    private final AuditLogsProducer auditLogsProducer = mock(AuditLogsProducer.class);
    private final AuditLogInternalService auditLogInternalService = mock(AuditLogInternalService.class);
    private final ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
    private final AuditLogEnhancer auditLogEnhancer = mock(AuditLogEnhancer.class);
    private final AuditLogAspect aspect = new AuditLogAspect();
    private SettingsDto previousLoggingSettings;

    @BeforeEach
    void setUp() {
        aspect.setAuditLogsProducer(auditLogsProducer);
        aspect.setAuditLogInternalService(auditLogInternalService);
        aspect.setAuditLogEnhancer(auditLogEnhancer);
        when(auditLogEnhancer.withObjectIdentities(any())).thenAnswer(invocation -> invocation.getArgument(0));
        aspect.setAuditResultOverride(mock(AuditResultOverride.class));
        aspect.setAuditOperationDataOverride(mock(AuditOperationDataOverride.class));
        aspect.setAuditAffiliationOverride(mock(AuditAffiliationOverride.class));
        ReflectionTestUtils.setField(aspect, "schemaVersion", "1.0");
        previousLoggingSettings = SettingsCache.getSettings(SettingsSection.LOGGING);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, auditLogsToTheDatabase());
    }

    @AfterEach
    @SuppressWarnings("unchecked")
    void restoreLoggingSettings() {
        Map<SettingsSection, SettingsDto> cache = (Map<SettingsSection, SettingsDto>) ReflectionTestUtils
                .getField(SettingsCache.class, "cache");
        if (previousLoggingSettings == null) {
            cache.remove(SettingsSection.LOGGING);
        } else {
            cache.put(SettingsSection.LOGGING, previousLoggingSettings);
        }
    }

    @Test
    void aSynchronousRecordIsWrittenBeforeTheCallReturns() throws Throwable {
        // given
        when(joinPoint.proceed()).thenReturn("released");

        // when
        Object result = aspect.log(joinPointOn("synchronousProbe"));

        // then
        assertEquals("released", result);
        verify(auditLogInternalService).log(any(LogRecord.class), eq(AuditLogOutput.DATABASE));
        verifyNoInteractions(auditLogsProducer);
    }

    @Test
    void aSynchronousRecordThatCannotBeWrittenFailsTheCall() throws Throwable {
        // given
        when(joinPoint.proceed()).thenReturn("released");
        doThrow(new IllegalStateException("audit store unavailable")).when(auditLogInternalService).log(any(), any());
        ProceedingJoinPoint call = joinPointOn("synchronousProbe");

        // when
        // then
        assertThrows(IllegalStateException.class, () -> aspect.log(call));
    }

    @Test
    void aFailedCallKeepsItsOwnErrorWhenItsRecordCannotBeWrittenEither() throws Throwable {
        // given
        when(joinPoint.proceed()).thenThrow(new ValidationException("refused"));
        doThrow(new IllegalStateException("audit store unavailable")).when(auditLogInternalService).log(any(), any());
        ProceedingJoinPoint call = joinPointOn("synchronousProbe");

        // when
        ValidationException thrown = assertThrows(ValidationException.class, () -> aspect.log(call));

        // then
        assertEquals(1, thrown.getSuppressed().length);
    }

    @Test
    void anOrdinaryRecordStillGoesThroughTheQueue() throws Throwable {
        // given
        when(joinPoint.proceed()).thenReturn("done");

        // when
        aspect.log(joinPointOn("asynchronousProbe"));

        // then
        verify(auditLogsProducer).produceMessage(any());
        verifyNoInteractions(auditLogInternalService);
    }

    /** A synchronous record follows the audit settings like any other: none is kept while audit logs are off. */
    @Test
    void aSynchronousRecordIsNotWrittenWhileAuditLogsAreOff() throws Throwable {
        // given
        LoggingSettingsDto off = auditLogsToTheDatabase();
        off.getAuditLogs().setOutput(AuditLogOutput.NONE);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, off);
        when(joinPoint.proceed()).thenReturn("released");

        // when
        Object result = aspect.log(joinPointOn("synchronousProbe"));

        // then
        assertEquals("released", result);
        verifyNoInteractions(auditLogInternalService, auditLogsProducer);
    }

    /** A synchronous record carries the object names a queued one does, filled in by the same enhancer. */
    @Test
    void aSynchronousRecordIsWrittenWithTheNamesOfItsObjects() throws Throwable {
        // given
        LogRecord named = LogRecord.builder().build();
        when(auditLogEnhancer.withObjectIdentities(any())).thenReturn(named);
        when(joinPoint.proceed()).thenReturn("released");

        // when
        aspect.log(joinPointOn("synchronousProbe"));

        // then
        verify(auditLogInternalService).log(named, AuditLogOutput.DATABASE);
    }

    private ProceedingJoinPoint joinPointOn(String probe) throws NoSuchMethodException {
        MethodSignature signature = mock(MethodSignature.class);
        when(signature.getMethod()).thenReturn(Probe.class.getDeclaredMethod(probe));
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getArgs()).thenReturn(new Object[0]);
        return joinPoint;
    }

    private static LoggingSettingsDto auditLogsToTheDatabase() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.DATABASE);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        return settings;
    }

    static final class Probe {

        @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM,
                operation = Operation.EXPORT, synchronous = true)
        void synchronousProbe() {
            // only its annotation is read
        }

        @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM,
                operation = Operation.EXPORT)
        void asynchronousProbe() {
            // only its annotation is read
        }
    }
}
