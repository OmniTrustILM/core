package com.otilm.core.service.est;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

class EstProtocolPropertiesTest {

    private static final Path SHIPPED_CONFIG = Path.of("src/main/resources/application.yml");
    private static final String INTERVAL = "est.protocol.issue-wait.interval";

    private static final ApplicationContextRunner RUNNER = new ApplicationContextRunner()
            .withUserConfiguration(EstProtocolConfig.class);

    @Test
    void bindsTheDocumentedDefault_whenNothingIsConfigured() {
        // given — no key of est.protocol is set

        // when
        EstProtocolProperties bound = bindWith();

        // then
        assertThat(bound.issueWait().interval()).isEqualTo(Duration.ofSeconds(1));
    }

    @Test
    void bindsTheConfiguredInterval_whenItIsSet() {
        // given
        var shorterInterval = Duration.ofMillis(250);

        // when
        EstProtocolProperties bound = bindWith(INTERVAL + "=250ms");

        // then
        assertThat(bound.issueWait().interval()).isEqualTo(shorterInterval);
    }

    /** An override such as an environment variable is often a bare number, which would otherwise be milliseconds. */
    @Test
    void bindsSeconds_whenTheIntervalHasNoUnit() {
        // given
        var bareNumber = 45;

        // when
        EstProtocolProperties bound = bindWith(INTERVAL + "=" + bareNumber);

        // then
        assertThat(bound.issueWait().interval()).isEqualTo(Duration.ofSeconds(bareNumber));
    }

    /** The integration tests read their own configuration, so only this reads the block an operator sees. */
    @Test
    void shipsTheDocumentedDefault_whenTheApplicationConfigurationIsRead() {
        // given
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new FileSystemResource(SHIPPED_CONFIG));

        // when
        Properties shipped = yaml.getObject();

        // then
        assertThat(shipped).isNotNull();
        assertThat(shipped.getProperty(INTERVAL)).isEqualTo("1s");
    }

    @ParameterizedTest
    @ValueSource(strings = {"99ms", "0s", "-1s"})
    void failsTheStart_whenTheIntervalIsShorterThanTheShortestAllowed(String tooShort) {
        // given
        var outOfRange = INTERVAL + "=" + tooShort;

        // when
        Throwable startupFailure = startupFailureWith(outOfRange);

        // then
        assertThat(startupFailure)
                .isNotNull()
                .rootCause()
                .hasMessageContaining(INTERVAL + " must be at least 100 milliseconds");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static EstProtocolProperties bindWith(String... properties) {
        AtomicReference<EstProtocolProperties> bound = new AtomicReference<>();
        RUNNER.withPropertyValues(properties).run(context -> bound.set(context.getBean(EstProtocolProperties.class)));
        return bound.get();
    }

    private static Throwable startupFailureWith(String... properties) {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        RUNNER.withPropertyValues(properties).run(context -> failure.set(context.getStartupFailure()));
        return failure.get();
    }
}
