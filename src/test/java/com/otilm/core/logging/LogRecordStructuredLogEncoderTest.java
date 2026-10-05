package com.otilm.core.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.settings.SettingsCache;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;
import org.slf4j.event.KeyValuePair;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class LogRecordStructuredLogEncoderTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final LoggerWrapper wrapper = new LoggerWrapper(Probe.class, Module.CRYPTOGRAPHIC_KEYS,
            Resource.CRYPTOGRAPHIC_KEY_ITEM);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private SettingsDto previousLoggingSettings;

    @BeforeEach
    void setUp() {
        previousLoggingSettings = SettingsCache.getSettings(SettingsSection.LOGGING);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, everythingLogged());
        logged.start();
        Logger logger = (Logger) LoggerFactory.getLogger(Probe.class);
        logger.setLevel(Level.DEBUG);
        logger.addAppender(logged);
    }

    @AfterEach
    @SuppressWarnings("unchecked")
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(Probe.class)).detachAppender(logged);
        Map<SettingsSection, SettingsDto> cache = (Map<SettingsSection, SettingsDto>) ReflectionTestUtils
                .getField(SettingsCache.class, "cache");
        if (previousLoggingSettings == null) {
            cache.remove(SettingsSection.LOGGING);
        } else {
            cache.put(SettingsSection.LOGGING, previousLoggingSettings);
        }
    }

    @Test
    void theTextMessageStaysTheRecordJson() throws Exception {
        wrapper.logAudited(auditRecord());

        JsonNode message = JSON.readTree(onlyEvent().getFormattedMessage());

        assertThat(message.get("operation").asText()).isEqualTo(Operation.EXPORT.getCode());
        assertThat(message.get("audited").asBoolean()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ecs", "logstash"})
    void theRecordIsWrittenOnceAsANestedObject(String format) throws Exception {
        wrapper.logAudited(auditRecord());
        ILoggingEvent event = onlyEvent();

        JsonNode line = JSON.readTree(encode(format, event));

        assertThat(line.get("log_record").isObject()).isTrue();
        assertThat(line.get("log_record")).isEqualTo(JSON.readTree(event.getFormattedMessage()));
        assertThat(line.get("message").asText()).isEqualTo("export keyItems success");
    }

    @Test
    void anEventMessageBecomesTheLineMessage() throws Exception {
        wrapper.logEvent(Operation.EXPORT, OperationResult.FAILURE, null, List.of(), "Connector refused the export");

        JsonNode line = JSON.readTree(encode("ecs", onlyEvent()));

        assertThat(line.get("message").asText()).isEqualTo("Connector refused the export");
        assertThat(line.at("/log/level").asText()).isEqualTo("ERROR");
        assertThat(line.at("/log_record/operationResult").asText()).isEqualTo(OperationResult.FAILURE.getCode());
    }

    @Test
    void aPlainEventKeepsItsMessage() throws Exception {
        LoggerFactory.getLogger(Probe.class).info("Plain {} line", "text");

        JsonNode line = JSON.readTree(encode("ecs", onlyEvent()));

        assertThat(line.get("message").asText()).isEqualTo("Plain text line");
        assertThat(line.has("log_record")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"gelf", "GELF"})
    void gelfIsRefusedAtStartup(String format) {
        LogRecordStructuredLogEncoder encoder = unstartedEncoder(format);

        assertThatIllegalStateException().isThrownBy(encoder::start).withMessageContaining("'ecs' or 'logstash'");
    }

    @Test
    @SuppressWarnings("deprecation")
    void aSummarizedEventChangesOnlyTheMessage() {
        LoggingEvent event = new LoggingEvent(Logger.class.getName(), (Logger) LoggerFactory.getLogger(Probe.class),
                Level.ERROR, "{\"version\":\"1.1\"}", new IllegalStateException("refused"), null);
        event.addMarker(MarkerFactory.getMarker("AUDIT"));
        event.setMDCPropertyMap(Map.of("log_actor_type", "USER"));
        event.addKeyValuePair(new KeyValuePair(SerializedLogRecord.KEY, new SerializedLogRecord(auditRecord(), "{}")));
        event.setCallerData(new StackTraceElement[]{new StackTraceElement("Probe", "run", "Probe.java", 7)});

        ILoggingEvent summarized = new LogRecordStructuredLogEncoder.SummarizedEvent(event, "summary");
        summarized.prepareForDeferredProcessing();

        assertThat(summarized.getFormattedMessage()).isEqualTo("summary");
        assertThat(summarized.getMessage()).isEqualTo("summary");
        assertThat(summarized.getArgumentArray()).isEmpty();
        assertThat(summarized)
                .returns(event.getThreadName(), ILoggingEvent::getThreadName)
                .returns(event.getLevel(), ILoggingEvent::getLevel)
                .returns(event.getLoggerName(), ILoggingEvent::getLoggerName)
                .returns(event.getLoggerContextVO(), ILoggingEvent::getLoggerContextVO)
                .returns(event.getThrowableProxy(), ILoggingEvent::getThrowableProxy)
                .returns(event.getCallerData(), ILoggingEvent::getCallerData)
                .returns(event.hasCallerData(), ILoggingEvent::hasCallerData)
                .returns(event.getMarkerList(), ILoggingEvent::getMarkerList)
                .returns(event.getMDCPropertyMap(), ILoggingEvent::getMDCPropertyMap)
                .returns(event.getMDCPropertyMap(), ILoggingEvent::getMdc)
                .returns(event.getTimeStamp(), ILoggingEvent::getTimeStamp)
                .returns(event.getNanoseconds(), ILoggingEvent::getNanoseconds)
                .returns(event.getInstant(), ILoggingEvent::getInstant)
                .returns(event.getSequenceNumber(), ILoggingEvent::getSequenceNumber)
                .returns(event.getKeyValuePairs(), ILoggingEvent::getKeyValuePairs);
    }

    private LogRecord auditRecord() {
        return wrapper
                .buildLogRecord(true, null, null, List.of(), Operation.EXPORT, OperationResult.SUCCESS, null, null,
                        null);
    }

    private ILoggingEvent onlyEvent() {
        assertThat(logged.list).hasSize(1);
        return logged.list.getFirst();
    }

    private static String encode(String format, ILoggingEvent event) {
        LogRecordStructuredLogEncoder encoder = unstartedEncoder(format);
        encoder.start();
        try {
            return new String(encoder.encode(event), StandardCharsets.UTF_8);
        } finally {
            encoder.stop();
        }
    }

    private static LogRecordStructuredLogEncoder unstartedEncoder(String format) {
        LoggerContext context = new LoggerContext();
        context.putObject(Environment.class.getName(), new MockEnvironment());
        LogRecordStructuredLogEncoder encoder = new LogRecordStructuredLogEncoder();
        encoder.setContext(context);
        encoder.setFormat(format);
        return encoder;
    }

    private static LoggingSettingsDto everythingLogged() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        ResourceLoggingSettingsDto eventLogs = new ResourceLoggingSettingsDto();
        eventLogs.setLogAllModules(true);
        eventLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(eventLogs);
        return settings;
    }

    private static final class Probe {
    }
}
