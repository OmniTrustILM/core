package com.otilm.core.config;

import com.otilm.core.messaging.jms.configuration.StatusPollProperties.PollSchedule;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the shipped discovery tick ladders, which the integration tests cannot: {@code src/test/resources} substitutes
 * its own {@code discovery.work} block wholesale.
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

    /**
     * An unanswered drain or processing tick waits only its own rung before the next try, so the attempt budget alone
     * sets how long a connector that stopped answering, or a batch that keeps failing, is tolerated.
     */
    @ParameterizedTest
    @ValueSource(strings = {"DRAIN", "PROCESS"})
    void theDrainAndProcessBudgetsKeepTheirWallClockAllowance(String workType) {
        // given
        Properties shipped = shipped();
        String prefix = "discovery.work.by-type." + workType;
        int maxAttempts = Integer.parseInt(shipped.getProperty(prefix + ".max-attempts"));
        PollSchedule ladder = new PollSchedule(rungs(shipped, prefix + ".delays"), maxAttempts);

        // when
        Duration tolerated = IntStream
                .rangeClosed(1, maxAttempts)
                .mapToObj(ladder::delayFor)
                .reduce(Duration.ZERO, Duration::plus);

        // then
        assertThat(tolerated).isGreaterThanOrEqualTo(Duration.ofMinutes(80));
    }

    /**
     * A lease shorter than one tick's worst case lets the sweep reclaim a row whose tick is still at the connector, and
     * publish it a second time. The worst case is a connector call's whole allowance (acquiring a connection,
     * connecting, waiting for the response) plus staging what it returned, before the tick renews the lease.
     */
    @Test
    void theLeaseOutlastsTheSlowestConnectorCall() {
        // given
        Properties shipped = shipped();
        Duration slowestCall = Stream
                .of("connector.api-client.pending-acquire-timeout", "connector.api-client.connect-timeout",
                        "connector.api-client.response-timeout")
                .map(key -> DurationStyle.detectAndParse(withoutPlaceholder(shipped.getProperty(key))))
                .reduce(Duration.ZERO, Duration::plus);
        Duration stagingMargin = Duration.ofSeconds(30);

        // when
        Duration lease = Duration.parse(withoutPlaceholder(shipped.getProperty("discovery.work.lease-duration")));

        // then
        assertThat(lease)
                .describedAs("a lease at or below the slowest tick lets the sweep publish a tick whose predecessor "
                        + "is still at the connector")
                .isGreaterThan(slowestCall.plus(stagingMargin));
    }

    private static List<Duration> rungs(Properties shipped, String delaysKey) {
        List<Duration> rungs = new ArrayList<>();
        for (int i = 0; shipped.getProperty(delaysKey + "[" + i + "]") != null; i++) {
            rungs.add(Duration.parse(shipped.getProperty(delaysKey + "[" + i + "]")));
        }
        assertThat(rungs).describedAs("%s must list at least one rung", delaysKey).isNotEmpty();
        return rungs;
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
