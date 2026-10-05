package com.otilm.core.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.util.LogbackMDCAdapter;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.status.Status;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.tasks.ScheduledLoggingFilter;
import io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Configures a fresh logger context from the shipped logback-spring.xml the way Spring Boot does, with the Spring
 * environment in the context; the test classpath otherwise runs on logback-test.xml and never reads it.
 */
class LogbackSpringConfigTest {

    private static final URL CONFIG = LogbackSpringConfigTest.class.getResource("/logback-spring.xml");

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "text"})
    void theTextFormatKeepsThePattern(String format) throws JoranException {
        LoggerContext context = configure(format, new MockEnvironment());

        assertThat(console(context).getEncoder()).isExactlyInstanceOf(PatternLayoutEncoder.class);
        assertThat(problems(context)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ecs", "logstash"})
    void aJsonFormatWritesThroughTheStructuredEncoder(String format) throws JoranException {
        LoggerContext context = configure(format, new MockEnvironment());

        assertThat(console(context).getEncoder()).isExactlyInstanceOf(LogRecordStructuredLogEncoder.class);
        assertThat(problems(context)).isEmpty();
    }

    @Test
    void bothFormatsFilterTheSameEvents() throws JoranException {
        List<Class<?>> textFilters = filterClasses(configure("text", new MockEnvironment()));
        List<Class<?>> jsonFilters = filterClasses(configure("ecs", new MockEnvironment()));

        assertThat(textFilters).contains(ScheduledLoggingFilter.class).isEqualTo(jsonFilters);
    }

    @Test
    void theOpenTelemetryAppendersAreAttachedWhenOpenTelemetryIsOn() throws JoranException {
        LoggerContext context = configure("ecs", new MockEnvironment().withProperty("otel.sdk.disabled", "FALSE"));

        assertThat(root(context).getAppender("OpenTelemetry")).isInstanceOf(OpenTelemetryAppender.class);
        assertThat(root(context).getAppender("SpanEvents")).isNotNull();
        assertThat(root(context).getAppender("CONSOLE")).isNotNull();
        assertThat(root(context).getLevel()).isEqualTo(Level.INFO);
        assertThat(problems(context)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "otel.sdk.disabled=true",
            "otel.sdk.disabled=false,otel.instrumentation.logback-appender.enabled=false",
            "otel.sdk.disabled=false,otel.instrumentation.common.default-enabled=false",
            "otel.file_format=1.0,otel.disabled=true,otel.sdk.disabled=false"})
    void theOpenTelemetryAppenderStaysOffWhenTheStarterWouldNotInstallTheSdk(String settings) throws JoranException {
        LoggerContext context = configure("ecs", environment(settings));

        assertThat(root(context).getAppender("OpenTelemetry")).isNull();
        assertThat(problems(context)).isEmpty();
    }

    @Test
    void theDeclarativeOpenTelemetrySwitchIsTheOneThatCounts() throws JoranException {
        LoggerContext context = configure("ecs",
                environment("otel.file_format=1.0,otel.disabled=false,otel.sdk.disabled=true"));

        assertThat(root(context).getAppender("OpenTelemetry")).isInstanceOf(OpenTelemetryAppender.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "otel.sdk.disabled=true",
            "otel.sdk.disabled=false,otel.instrumentation.logback-appender.enabled=false"})
    void spanEventsAreAttachedWhateverTheLogExportSwitch(String settings) throws JoranException {
        LoggerContext context = configure("ecs", environment(settings));

        assertThat(root(context).getAppender("SpanEvents")).isNotNull();
    }

    @Test
    void theOpenTelemetryAppenderExportsTheRecordJsonAsTheBody() throws Exception {
        LoggerContext context = configure("ecs", new MockEnvironment().withProperty("otel.sdk.disabled", "false"));
        OpenTelemetryAppender appender = (OpenTelemetryAppender) root(context).getAppender("OpenTelemetry");
        Collecting exporter = new Collecting();
        OpenTelemetrySdk sdk = OpenTelemetrySdk
                .builder()
                .setLoggerProvider(SdkLoggerProvider
                        .builder()
                        .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
                        .build())
                .build();
        appender.setOpenTelemetry(sdk);
        Logger probeLogger = (Logger) LoggerFactory.getLogger(Probe.class);
        probeLogger.addAppender(appender);
        SettingsDto previousSettings = SettingsCache.getSettings(SettingsSection.LOGGING);
        new SettingsCache().cacheSettings(SettingsSection.LOGGING, auditLogsOn());
        try {
            LoggerWrapper wrapper = new LoggerWrapper(Probe.class, Module.CERTIFICATES, Resource.CERTIFICATE);
            wrapper
                    .logAudited(wrapper
                            .buildLogRecord(true, null, null, List.of(), Operation.ISSUE, OperationResult.SUCCESS, null,
                                    null, null));
        } finally {
            probeLogger.detachAppender(appender);
            restore(previousSettings);
            sdk.close();
        }

        assertThat(exporter.records).hasSize(1);
        LogRecordData exported = exporter.records.getFirst();
        Map<String, Object> attributes = new HashMap<>();
        exported.getAttributes().forEach((key, value) -> attributes.put(key.getKey(), value));
        assertThat(new ObjectMapper().readTree(exported.getBodyValue().asString()).get("operation").asText())
                .isEqualTo(Operation.ISSUE.getCode());
        assertThat(attributes).containsEntry("code.function", "logAudited").doesNotContainKey(SerializedLogRecord.KEY);
    }

    private static LoggerContext configure(String structuredFormat, MockEnvironment environment) throws JoranException {
        LoggerContext context = new LoggerContext();
        context.setMDCAdapter(new LogbackMDCAdapter());
        context.putObject(Environment.class.getName(), environment);
        if (structuredFormat != null) {
            context.putProperty("CONSOLE_LOG_STRUCTURED_FORMAT", structuredFormat);
        }
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        configurator.doConfigure(CONFIG);
        return context;
    }

    private static MockEnvironment environment(String settings) {
        MockEnvironment environment = new MockEnvironment();
        for (String setting : settings.split(",")) {
            String[] keyValue = setting.split("=");
            environment.withProperty(keyValue[0], keyValue[1]);
        }
        return environment;
    }

    private static Logger root(LoggerContext context) {
        return context.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    }

    private static ConsoleAppender<ILoggingEvent> console(LoggerContext context) {
        return (ConsoleAppender<ILoggingEvent>) root(context).getAppender("CONSOLE");
    }

    private static List<Class<?>> filterClasses(LoggerContext context) {
        List<Class<?>> classes = new ArrayList<>();
        console(context).getCopyOfAttachedFiltersList().forEach(filter -> classes.add(filter.getClass()));
        return classes;
    }

    private static List<String> problems(LoggerContext context) {
        List<String> problems = new ArrayList<>();
        for (Status status : context.getStatusManager().getCopyOfStatusList()) {
            if (status.getLevel() >= Status.WARN) {
                problems.add(status.getMessage());
            }
        }
        return problems;
    }

    private static LoggingSettingsDto auditLogsOn() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        return settings;
    }

    @SuppressWarnings("unchecked")
    private static void restore(SettingsDto previousSettings) {
        Map<SettingsSection, SettingsDto> cache = (Map<SettingsSection, SettingsDto>) ReflectionTestUtils
                .getField(SettingsCache.class, "cache");
        if (previousSettings == null) {
            cache.remove(SettingsSection.LOGGING);
        } else {
            cache.put(SettingsSection.LOGGING, previousSettings);
        }
    }

    private static final class Probe {
    }

    private static final class Collecting implements LogRecordExporter {

        private final List<LogRecordData> records = new CopyOnWriteArrayList<>();

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            records.addAll(logs);
            return CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode flush() {
            return CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode shutdown() {
            return CompletableResultCode.ofSuccess();
        }
    }
}
