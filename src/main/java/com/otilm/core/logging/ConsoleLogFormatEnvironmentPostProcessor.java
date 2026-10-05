package com.otilm.core.logging;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

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

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String format = environment.getProperty(CONSOLE_FORMAT_PROPERTY, TEXT).trim();
        if (StringUtils.hasText(format) && !TEXT.equalsIgnoreCase(format)) {
            environment
                    .getPropertySources()
                    .addLast(
                            new MapPropertySource(CONSOLE_FORMAT_PROPERTY, Map.of(STRUCTURED_FORMAT_PROPERTY, format)));
        }
    }

    /** After the configuration files are loaded, so a default declared in application.yml is seen. */
    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }
}
