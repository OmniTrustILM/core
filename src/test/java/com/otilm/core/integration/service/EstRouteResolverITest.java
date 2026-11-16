package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.EstRouteResolver;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class EstRouteResolverITest extends BaseSpringBootTest {

    private static final String NO_CONNECTOR = "RA Profile 'devices-ra' has no authority with a connector";

    @Autowired
    private EstRouteResolver resolver;

    @Autowired
    private EstRouteSeeder seeder;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void captureTheResolverLog() {
        logged.start();
        Logger logger = (Logger) LoggerFactory.getLogger(EstRouteResolver.class);
        logger.setLevel(Level.DEBUG);
        logger.addAppender(logged);
    }

    @AfterEach
    void releaseTheResolverLog() {
        Logger logger = (Logger) LoggerFactory.getLogger(EstRouteResolver.class);
        logger.detachAppender(logged);
        logger.setLevel(null);
        logged.stop();
    }

    // ── NoLabel ───────────────────────────────────────────────────────────────

    @Nested
    class NoLabel {

        @Test
        void returnsRouteOfTheEnabledSystemDefault() {
            // given
            String noLabel = null;
            seeder.seedEstProfile("est-other", true, seeder.seedRaProfile("other-ra"));
            RaProfile defaultRaProfile = seeder.seedRaProfile("devices-ra");
            EstProfile systemDefault = seeder.seedSystemDefault(defaultRaProfile);

            // when
            Optional<EstRoute> route = resolver.resolve(noLabel);

            // then
            assertRoute(route, systemDefault, defaultRaProfile, false);
        }

        @Test
        void returnsEmpty_whenNoProfileIsTheSystemDefault() {
            // given
            String noLabel = null;
            seeder.seedEstProfile("est-devices", true, seeder.seedRaProfile("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(noLabel);

            // then
            assertNoRoute(route, "no EST Profile is the system default");
        }

        @Test
        void returnsEmpty_whenSystemDefaultIsDisabled() {
            // given
            String noLabel = null;
            seeder.markAsSystemDefault(seeder.seedEstProfile("est-default", false, seeder.seedRaProfile("devices-ra")));

            // when
            Optional<EstRoute> route = resolver.resolve(noLabel);

            // then
            assertNoRoute(route, "EST Profile 'est-default' is disabled");
        }

        @Test
        void returnsEmpty_whenOnlyAnRaProfileHasEstActivated() {
            // given
            String noLabel = null;
            seeder.activateEst(seeder.seedRaProfile("devices-ra"), seeder.seedEstProfile("est-devices", true, null));

            // when
            Optional<EstRoute> route = resolver.resolve(noLabel);

            // then
            assertNoRoute(route, "no EST Profile is the system default");
        }
    }

    // ── EstProfileLabel ───────────────────────────────────────────────────────

    @Nested
    class EstProfileLabel {

        @Test
        void returnsRouteThroughItsDefaultRaProfile() {
            // given
            var label = "est-devices";
            RaProfile defaultRaProfile = seeder.seedRaProfile("devices-ra");
            EstProfile estProfile = seeder.seedEstProfile(label, true, defaultRaProfile);

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertRoute(route, estProfile, defaultRaProfile, false);
        }

        @Test
        void returnsEmpty_whenProfileHasNoDefaultRaProfile() {
            // given
            var label = "est-devices";
            seeder.seedEstProfile(label, true, null);

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, "EST Profile 'est-devices' has no default RA Profile");
        }

        @Test
        void returnsEmpty_whenProfileIsDisabled() {
            // given
            var label = "est-devices";
            seeder.seedEstProfile(label, false, seeder.seedRaProfile("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, "EST Profile 'est-devices' is disabled");
        }

        @Test
        void returnsEmpty_whenDefaultRaProfileIsDisabled() {
            // given
            var label = "est-devices";
            seeder.seedEstProfile(label, true, seeder.seedRaProfile("devices-ra", false));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, "RA Profile 'devices-ra' is disabled");
        }

        @Test
        void returnsEmpty_whenAuthorityOfDefaultRaProfileHasNoConnector() {
            // given
            var label = "est-devices";
            seeder.seedEstProfile(label, true, seeder.seedRaProfileWithoutConnector("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, NO_CONNECTOR);
        }

        @Test
        void returnsRoute_whenAnRaProfileOfTheSameNameHasNoEstActivated() {
            // given
            var sharedLabel = "devices";
            RaProfile defaultRaProfile = seeder.seedRaProfile("default-ra");
            EstProfile estProfile = seeder.seedEstProfile(sharedLabel, true, defaultRaProfile);
            seeder.seedRaProfile(sharedLabel);

            // when
            Optional<EstRoute> route = resolver.resolve(sharedLabel);

            // then
            assertRoute(route, estProfile, defaultRaProfile, false);
        }
    }

    // ── RaProfileLabel ────────────────────────────────────────────────────────

    @Nested
    class RaProfileLabel {

        @Test
        void returnsRouteToItsActivatedEstProfile() {
            // given
            var label = "devices-ra";
            EstProfile estProfile = seeder.seedEstProfile("est-devices", true, null);
            RaProfile raProfile = seeder.activateEst(seeder.seedRaProfile(label), estProfile);

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertRoute(route, estProfile, raProfile, true);
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(booleans = false)
        void returnsEmpty_whenRaProfileIsNotEnabled(Boolean notEnabled) {
            // given
            var label = "devices-ra";
            seeder
                    .activateEst(seeder.seedRaProfile(label, notEnabled),
                            seeder.seedEstProfile("est-devices", true, null));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, "RA Profile 'devices-ra' is disabled");
        }

        @Test
        void returnsEmpty_whenActivatedEstProfileIsDisabled() {
            // given
            var label = "devices-ra";
            seeder.activateEst(seeder.seedRaProfile(label), seeder.seedEstProfile("est-devices", false, null));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, "EST Profile 'est-devices' is disabled");
        }

        @Test
        void returnsEmpty_whenRaProfileHasNoAuthority() {
            // given
            var label = "devices-ra";
            seeder
                    .activateEst(seeder.seedRaProfileWithoutAuthority(label),
                            seeder.seedEstProfile("est-devices", true, null));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertNoRoute(route, NO_CONNECTOR);
        }
    }

    // ── AmbiguousOrUnknownLabel ───────────────────────────────────────────────

    @Nested
    class AmbiguousOrUnknownLabel {

        @ParameterizedTest(name = "enabled: EST Profile {0}, RA Profile {1}, activated EST Profile {2}")
        @CsvSource({"true, true, true", "false, true, true", "true, false, true", "true, true, false"})
        void returnsEmpty_whenLabelNamesBothAnEstProfileAndAnRaProfile(boolean estProfileEnabled,
                boolean raProfileEnabled, boolean activatedProfileEnabled) {
            // given
            var sharedLabel = "devices";
            seeder.seedEstProfile(sharedLabel, estProfileEnabled, seeder.seedRaProfile("default-ra"));
            seeder
                    .activateEst(seeder.seedRaProfile(sharedLabel, raProfileEnabled),
                            seeder.seedEstProfile("est-activated", activatedProfileEnabled, null));

            // when
            Optional<EstRoute> route = resolver.resolve(sharedLabel);

            // then
            assertNoRoute(route, "matches both an EST Profile and an RA Profile");
        }

        @Test
        void returnsEmpty_whenLabelNamesNoEstProfileNorActivatedRaProfile() {
            // given
            var raProfileLabelWithoutEst = "devices-ra";
            seeder.seedEstProfile("est-devices", true, seeder.seedRaProfile(raProfileLabelWithoutEst));

            // when
            Optional<EstRoute> route = resolver.resolve(raProfileLabelWithoutEst);

            // then
            assertNoRoute(route, "matches no EST Profile and no RA Profile with EST activated");
        }
    }

    // ── UnusableLabel ─────────────────────────────────────────────────────────

    @Nested
    class UnusableLabel {

        @ParameterizedTest
        @ValueSource(strings = {"cacerts", "..", "a b", ""})
        void returnsEmpty(String unusableLabel) {
            // given
            seeder.seedEstProfile(unusableLabel, true, seeder.seedRaProfile("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(unusableLabel);

            // then
            assertNoRoute(route, "unusable label");
        }

        @Test
        void omitsTheLabelFromTheLog() {
            // given
            var forgedLine = "forged";
            var labelForgingALogLine = "x\r\n" + forgedLine;

            // when
            Optional<EstRoute> route = resolver.resolve(labelForgingALogLine);

            // then
            assertNoRoute(route, "unusable label");
            assertThat(logged.list)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .isNotEmpty()
                    .noneMatch(message -> message.contains(forgedLine));
        }
    }

    // ── RouteLabel ────────────────────────────────────────────────────────────

    @Nested
    class RouteLabel {

        @Test
        void returnsLabel_whenRouteWasNamed() {
            // given
            var label = "est-devices";
            seeder.seedEstProfile(label, true, seeder.seedRaProfile("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertThat(route).hasValueSatisfying(resolved -> assertThat(resolved.label()).isEqualTo(label));
        }

        @Test
        void returnsLabel_whenRouteWasNamedByAnRaProfile() {
            // given
            var label = "devices-ra";
            seeder.activateEst(seeder.seedRaProfile(label), seeder.seedEstProfile("est-devices", true, null));

            // when
            Optional<EstRoute> route = resolver.resolve(label);

            // then
            assertThat(route).hasValueSatisfying(resolved -> assertThat(resolved.label()).isEqualTo(label));
        }

        @Test
        void returnsNoLabel_whenRouteIsTheSystemDefault() {
            // given
            String noLabel = null;
            seeder.seedSystemDefault(seeder.seedRaProfile("devices-ra"));

            // when
            Optional<EstRoute> route = resolver.resolve(noLabel);

            // then
            assertThat(route).hasValueSatisfying(resolved -> assertThat(resolved.label()).isNull());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void assertNoRoute(Optional<EstRoute> route, String reason) {
        assertThat(route).isEmpty();

        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
            assertThat(event.getFormattedMessage()).contains(reason);
        });
    }

    /** The route's RA Profile is read after the resolver returned, with no session left to load its authority. */
    private static void assertRoute(Optional<EstRoute> route, EstProfile estProfile, RaProfile raProfile,
            boolean raProfileRoute) {
        assertThat(route).hasValueSatisfying(resolved -> {
            assertThat(resolved.estProfile().getUuid()).isEqualTo(estProfile.getUuid());
            assertThat(resolved.raProfile().getUuid()).isEqualTo(raProfile.getUuid());
            assertThat(resolved.raProfileRoute()).isEqualTo(raProfileRoute);
            assertThat(resolved.raProfile().getAuthorityInstanceReference().getConnector().getFunctionGroups())
                    .isNotEmpty();
        });
    }
}
