package com.otilm.core.config;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.annotation.ImportCandidates;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boot 4 moved its auto-configurations into feature modules, and a test context still loads without one. So this checks
 * that the auto-configurations the application ran with on Boot 3.5 are still present.
 */
class ProductionAutoConfigurationTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration",
            "org.springframework.boot.session.autoconfigure.SessionAutoConfiguration",
            "org.springframework.boot.jms.autoconfigure.health.JmsHealthContributorAutoConfiguration",
            "org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration"})
    void theApplicationRunsWithTheAutoConfigurationOfTheBoot35Line(String autoConfiguration) {
        List<String> candidates = ImportCandidates
                .load(AutoConfiguration.class, getClass().getClassLoader())
                .getCandidates();

        assertThat(candidates).contains(autoConfiguration);
    }
}
