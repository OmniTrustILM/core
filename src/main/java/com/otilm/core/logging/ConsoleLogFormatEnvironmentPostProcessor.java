package com.otilm.core.logging;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Turns {@code logging.console-format} into Spring Boot's structured console format, and leaves the Boot property out
 * for the text format. Boot switches the startup banner off whenever {@code logging.structured.format.console} is
 * present, whatever its value, so declaring it for text would change the console output of a platform that never chose
 * a format.
 */
public class ConsoleLogFormatEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String CONSOLE_FORMAT_PROPERTY = "logging.console-format";

    static final String STRUCTURED_FORMAT_PROPERTY = "logging.structured.format.console";

    private static final String TEXT = "text";

    private static final Set<String> JSON_FORMATS = Set.of("ecs", "logstash");

    /**
     * Refuses anything but text, ecs and logstash with one message naming them; Boot's own error for an unknown format
     * would also offer gelf, which LogRecordStructuredLogEncoder refuses.
     */
    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String configured = environment.getProperty(CONSOLE_FORMAT_PROPERTY, TEXT);
        String format = configured.trim().toLowerCase(Locale.ROOT);
        if (format.isEmpty() || TEXT.equals(format)) {
            return;
        }
        if (!JSON_FORMATS.contains(format)) {
            throw new IllegalStateException(
                    "Console log format '%s' is not supported: set PLATFORM_LOG_FORMAT (%s) to text, ecs or logstash"
                            .formatted(configured, CONSOLE_FORMAT_PROPERTY));
        }
        environment
                .getPropertySources()
                .addLast(new MapPropertySource(ConsoleLogFormatEnvironmentPostProcessor.class.getSimpleName(),
                        Map.of(STRUCTURED_FORMAT_PROPERTY, format)));
    }

    /** After the configuration files are loaded, so a default declared in application.yml is seen. */
    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }
}
