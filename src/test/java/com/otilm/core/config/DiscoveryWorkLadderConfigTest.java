package com.otilm.core.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the shipped discovery tick ladders, which the integration tests cannot: {@code src/test/resources} substitutes
 * its own {@code discovery.work} block wholesale.
 *
 * <p>
 * The status tick is the only path by which a Discovery Provider's counters and its view of a run reach the platform,
 * so its slowest rung is how stale progress can be and how late the platform learns a scan finished.
 */
class DiscoveryWorkLadderConfigTest {

    private static final Path SHIPPED_CONFIG = Path.of("src/main/resources/application.yml");

    private static final String STATUS_DELAYS = "discovery.work.by-type.STATUS.delays";

    @Test
    void theStatusTickHasItsOwnLadderRatherThanTheSharedDefaults() {
        assertThat(shipped().getProperty(STATUS_DELAYS + "[0]"))
                .describedAs("%s must be declared; without it the status tick falls back to discovery.work.defaults, "
                        + "whose ceiling is minutes", STATUS_DELAYS)
                .isNotNull();
    }

    @Test
    void theSlowestStatusRungSitsAtOrBelowTheClaimFloor() {
        Properties shipped = shipped();
        Duration claimFloor = Duration.parse(withoutPlaceholder(shipped.getProperty("discovery.work.claim-floor")));

        assertThat(slowestRung(shipped, STATUS_DELAYS))
                .describedAs("a status rung above the claim floor is the run's progress staleness, and the drain "
                        + "tick is already calling the same provider at the floor")
                .isLessThanOrEqualTo(claimFloor);
    }

    /**
     * Shorter rungs must not quietly shorten how long an unanswering provider is tolerated: the budget is counted in
     * attempts, so halving the interval halves the wall-clock allowance unless the count rises with it.
     */
    @Test
    void theStatusBudgetStillCoversHoursOfSilence() {
        Properties shipped = shipped();
        int maxAttempts = Integer.parseInt(shipped.getProperty("discovery.work.by-type.STATUS.max-attempts"));

        Duration tolerated = slowestRung(shipped, STATUS_DELAYS).multipliedBy(maxAttempts);

        assertThat(tolerated).isGreaterThan(Duration.ofHours(24));
    }

    private static Duration slowestRung(Properties shipped, String delaysKey) {
        Duration slowest = null;
        for (int i = 0; shipped.getProperty(delaysKey + "[" + i + "]") != null; i++) {
            slowest = Duration.parse(shipped.getProperty(delaysKey + "[" + i + "]"));
        }
        assertThat(slowest).describedAs("%s must list at least one rung", delaysKey).isNotNull();
        return slowest;
    }

    /** Values here are written as {@code ${ENV_VAR:default}}; the default is what ships. */
    private static String withoutPlaceholder(String value) {
        if (value == null || !value.startsWith("${")) {
            return value;
        }
        return value.substring(value.indexOf(':') + 1, value.length() - 1);
    }

    private static Properties shipped() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new FileSystemResource(SHIPPED_CONFIG));
        Properties flattened = yaml.getObject();
        assertThat(flattened).describedAs("%s must be readable", SHIPPED_CONFIG).isNotNull();
        return flattened;
    }
}
