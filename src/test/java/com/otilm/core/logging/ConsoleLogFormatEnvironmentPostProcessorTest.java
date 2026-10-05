package com.otilm.core.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.mock.env.MockEnvironment;

import static com.otilm.core.logging.ConsoleLogFormatEnvironmentPostProcessor.CONSOLE_FORMAT_PROPERTY;
import static com.otilm.core.logging.ConsoleLogFormatEnvironmentPostProcessor.STRUCTURED_FORMAT_PROPERTY;
import static org.assertj.core.api.Assertions.assertThat;

class ConsoleLogFormatEnvironmentPostProcessorTest {

    private final ConsoleLogFormatEnvironmentPostProcessor postProcessor = new ConsoleLogFormatEnvironmentPostProcessor();

    @Test
    void anUnsetFormatLeavesStructuredLoggingOff() {
        MockEnvironment environment = new MockEnvironment();

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.containsProperty(STRUCTURED_FORMAT_PROPERTY)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"text", "TEXT", "", " "})
    void theTextFormatLeavesStructuredLoggingOff(String format) {
        MockEnvironment environment = new MockEnvironment().withProperty(CONSOLE_FORMAT_PROPERTY, format);

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.containsProperty(STRUCTURED_FORMAT_PROPERTY)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ecs", " logstash "})
    void aJsonFormatBecomesTheStructuredFormat(String format) {
        MockEnvironment environment = new MockEnvironment().withProperty(CONSOLE_FORMAT_PROPERTY, format);

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty(STRUCTURED_FORMAT_PROPERTY)).isEqualTo(format.trim());
    }

    @Test
    void anExplicitStructuredFormatWins() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(CONSOLE_FORMAT_PROPERTY, "ecs")
                .withProperty(STRUCTURED_FORMAT_PROPERTY, "logstash");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty(STRUCTURED_FORMAT_PROPERTY)).isEqualTo("logstash");
    }
}
