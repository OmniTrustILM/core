package com.otilm.core.aop;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.secret.SecretRequestDto;
import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.logging.AuditLogEnhancer;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.jms.producers.AuditLogsProducer;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.settings.SettingsCache;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    /** An operation may name its object by its UUID alone, and leave its name for the enhancer to fill in. */
    @Test
    void anObjectNamedByItsUuidAloneIsRecordedByIt() throws Throwable {
        // given
        LoggingHelper.clearLogResourceObject();
        UUID objectUuid = UUID.randomUUID();
        when(joinPoint.proceed()).thenAnswer(invocation -> {
            LoggingHelper.putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY_ITEM, false, objectUuid.toString(), null);
            return "released";
        });
        ArgumentCaptor<LogRecord> recorded = ArgumentCaptor.forClass(LogRecord.class);

        // when
        try {
            aspect.log(joinPointOn("synchronousProbe"));
        } finally {
            LoggingHelper.clearLogResourceObject();
        }

        // then
        verify(auditLogInternalService).log(recorded.capture(), eq(AuditLogOutput.DATABASE));
        assertEquals(List.of(new ResourceObjectIdentity(null, objectUuid)), recorded.getValue().resource().objects());
    }

    /** A verbose record holds what the call was given, with its secrets redacted. */
    @Test
    @SuppressWarnings("unchecked")
    void aVerboseRecordHoldsTheArgumentWithItsSecretRedacted() throws Throwable {
        // given
        LoggingSettingsDto verbose = auditLogsToTheDatabase();
        verbose.getAuditLogs().setVerbose(true);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, verbose);
        SecretRequestDto request = new SecretRequestDto();
        request.setName("probe");
        request.setSecret(new BasicAuthSecretContent("alice", "basic-auth-password"));
        when(joinPoint.proceed()).thenReturn("released");
        ArgumentCaptor<LogRecord> recorded = ArgumentCaptor.forClass(LogRecord.class);

        // when
        aspect.log(joinPointOn("verboseProbe", new Class<?>[]{SecretRequestDto.class}, request));

        // then
        verify(auditLogInternalService).log(recorded.capture(), eq(AuditLogOutput.DATABASE));
        Map<String, Object> recordedRequest = (Map<String, Object>) recorded.getValue().additionalData().get("request");
        Map<String, Object> secret = (Map<String, Object>) recordedRequest.get("secret");
        assertEquals("alice", secret.get("username"));
        assertEquals("***", secret.get("password"));
    }

    /** A verbose record holds a secret attribute value redacted too. */
    @Test
    void aVerboseRecordHoldsASecretAttributeValueRedacted() throws Throwable {
        // given
        LoggingSettingsDto verbose = auditLogsToTheDatabase();
        verbose.getAuditLogs().setVerbose(true);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, verbose);
        List<RequestAttribute> attributes = List
                .of(new RequestAttributeV2(UUID.randomUUID(), "password", AttributeContentType.SECRET,
                        List
                                .of(new SecretAttributeContentV2(null,
                                        new SecretAttributeContentData("attribute-secret-value")))));
        when(joinPoint.proceed()).thenReturn("released");
        ArgumentCaptor<LogRecord> captor = ArgumentCaptor.forClass(LogRecord.class);

        // when
        aspect.log(joinPointOn("verboseAttributesProbe", new Class<?>[]{List.class}, attributes));

        // then
        verify(auditLogInternalService).log(captor.capture(), eq(AuditLogOutput.DATABASE));
        LogRecord logRecord = captor.getValue();
        String recorded = ObjectMapperFactory.auditLog().writeValueAsString(logRecord.additionalData());
        assertTrue(recorded.contains("\"secret\":\"***\""));
        assertFalse(recorded.contains("attribute-secret-value"));
    }

    private ProceedingJoinPoint joinPointOn(String probe) throws NoSuchMethodException {
        return joinPointOn(probe, new Class<?>[0]);
    }

    private ProceedingJoinPoint joinPointOn(String probe, Class<?>[] parameterTypes, Object... arguments)
            throws NoSuchMethodException {
        MethodSignature signature = mock(MethodSignature.class);
        when(signature.getMethod()).thenReturn(Probe.class.getDeclaredMethod(probe, parameterTypes));
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getArgs()).thenReturn(arguments);
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

        @AuditLogged(module = Module.SECRETS, resource = Resource.SECRET, operation = Operation.CREATE,
                synchronous = true)
        void verboseProbe(SecretRequestDto request) {
            // only its annotation and parameters are read
        }

        @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM,
                operation = Operation.EXPORT, synchronous = true)
        void verboseAttributesProbe(List<RequestAttribute> exportAttributes) {
            // only its annotation and parameters are read
        }
    }
}
